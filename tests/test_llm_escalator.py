# SPDX-License-Identifier: MIT
"""Tests for F-3 (LLM escalation client) and F-4 (P2-5 signing trace escalation)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from engine.extraction.signing_tracer import LLM_THRESHOLD, escalate
from engine.ir.models import SigningComponent, SigningTrace
from engine.llm import escalator

# ── helpers ────────────────────────────────────────────────────────────────────


class _SimpleSchema(BaseModel):
    value: str
    score: float


def _mock_anthropic(
    response_text: str, input_tokens: int = 100, output_tokens: int = 50
) -> MagicMock:
    """Patch anthropic.AsyncAnthropic to return a fixed response."""
    usage = MagicMock()
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens

    content = MagicMock()
    content.text = response_text

    message = MagicMock()
    message.content = [content]
    message.usage = usage

    client = MagicMock()
    client.messages.create = AsyncMock(return_value=message)

    anthropic_mod = MagicMock()
    anthropic_mod.AsyncAnthropic.return_value = client
    anthropic_mod.RateLimitError = type("RateLimitError", (Exception,), {})

    return anthropic_mod


def _low_trace(unresolved: list[str] | None = None) -> SigningTrace:
    return SigningTrace(
        algorithm="HMAC-SHA256",
        components=[],
        key_source=None,
        source_method="com.example.Client",
        confidence=0.3,
        unresolved=unresolved or ["apiKey", "timestamp"],
    )


# ── escalator unit tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_call_returns_none_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = await escalator.call("sys", "user", _SimpleSchema)
    assert result is None


@pytest.mark.asyncio
async def test_call_returns_none_when_anthropic_not_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    with patch.dict("sys.modules", {"anthropic": None}):
        result = await escalator.call("sys", "user", _SimpleSchema)
    assert result is None


@pytest.mark.asyncio
async def test_call_returns_validated_instance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    ant = _mock_anthropic('{"value": "hello", "score": 0.9}')
    with patch.dict("sys.modules", {"anthropic": ant}):
        result = await escalator.call("sys", "user", _SimpleSchema)
    assert isinstance(result, _SimpleSchema)
    assert result.value == "hello"
    assert result.score == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_call_returns_none_on_invalid_json(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    ant = _mock_anthropic("not json at all")
    with patch.dict("sys.modules", {"anthropic": ant}):
        result = await escalator.call("sys", "user", _SimpleSchema)
    assert result is None


@pytest.mark.asyncio
async def test_call_returns_none_on_schema_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    ant = _mock_anthropic('{"wrong_key": 123}')
    with patch.dict("sys.modules", {"anthropic": ant}):
        result = await escalator.call("sys", "user", _SimpleSchema)
    assert result is None


@pytest.mark.asyncio
async def test_call_retries_on_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    usage = MagicMock()
    usage.input_tokens = 10
    usage.output_tokens = 5

    content = MagicMock()
    content.text = '{"value": "ok", "score": 1.0}'

    message = MagicMock()
    message.content = [content]
    message.usage = usage

    client = MagicMock()
    RateLimitError = type("RateLimitError", (Exception,), {})
    # First call raises 429, second succeeds
    client.messages.create = AsyncMock(side_effect=[RateLimitError("rate limited"), message])

    ant = MagicMock()
    ant.AsyncAnthropic.return_value = client
    ant.RateLimitError = RateLimitError

    with (
        patch.dict("sys.modules", {"anthropic": ant}),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await escalator.call("sys", "user", _SimpleSchema)

    assert result is not None
    assert result.value == "ok"
    assert client.messages.create.call_count == 2


@pytest.mark.asyncio
async def test_call_returns_none_after_all_retries_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    RateLimitError = type("RateLimitError", (Exception,), {})
    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=RateLimitError("rate limited"))

    ant = MagicMock()
    ant.AsyncAnthropic.return_value = client
    ant.RateLimitError = RateLimitError

    with (
        patch.dict("sys.modules", {"anthropic": ant}),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        result = await escalator.call("sys", "user", _SimpleSchema)

    assert result is None


@pytest.mark.asyncio
async def test_call_returns_none_on_arbitrary_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = MagicMock()
    client.messages.create = AsyncMock(side_effect=ConnectionError("network down"))

    ant = MagicMock()
    ant.AsyncAnthropic.return_value = client
    ant.RateLimitError = type("RateLimitError", (Exception,), {})

    with patch.dict("sys.modules", {"anthropic": ant}):
        result = await escalator.call("sys", "user", _SimpleSchema)

    assert result is None


def test_estimate_cost_nonzero() -> None:
    cost = escalator._estimate_cost("claude-sonnet-4-6", 1000, 500)
    assert cost > 0


def test_sha8_returns_8_chars() -> None:
    assert len(escalator._sha8("hello")) == 8


# ── signing trace escalation (F-4) tests ─────────────────────────────────────


@pytest.mark.asyncio
async def test_escalate_passes_through_high_confidence_traces(tmp_path: Path) -> None:
    high = SigningTrace(
        algorithm="HMAC-SHA256",
        components=[SigningComponent(kind="timestamp", variable_name="ts")],
        key_source=None,
        source_method="com.example.Client",
        confidence=LLM_THRESHOLD + 0.1,
        unresolved=[],
    )
    result = await escalate([high], tmp_path)
    assert result[0].confidence == high.confidence


@pytest.mark.asyncio
async def test_escalate_passes_through_when_no_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    tr = _low_trace()
    result = await escalate([tr], tmp_path)
    assert result[0].confidence == tr.confidence


@pytest.mark.asyncio
async def test_escalate_enriches_unresolved_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    llm_response = (
        '{"inputs": ['
        '{"name": "apiKey", "kind": "secret_key", "order": 0},'
        '{"name": "timestamp", "kind": "timestamp", "order": 1}'
        '], "format_string": "{apiKey}:{timestamp}", "confidence": 0.85}'
    )
    ant = _mock_anthropic(llm_response)
    with patch.dict("sys.modules", {"anthropic": ant}):
        result = await escalate([_low_trace()], tmp_path)

    tr = result[0]
    assert tr.confidence >= 0.85
    kinds = {c.variable_name: c.kind for c in tr.components}
    assert kinds.get("apiKey") == "secret_key"
    assert kinds.get("timestamp") == "timestamp"


@pytest.mark.asyncio
async def test_escalate_clears_resolved_variables_from_unresolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    llm_response = (
        '{"inputs": [{"name": "apiKey", "kind": "secret_key", "order": 0}],"confidence": 0.8}'
    )
    ant = _mock_anthropic(llm_response)
    with patch.dict("sys.modules", {"anthropic": ant}):
        result = await escalate([_low_trace(["apiKey", "timestamp"])], tmp_path)

    tr = result[0]
    # apiKey was resolved; timestamp still unresolved
    assert "apiKey" not in tr.unresolved
    assert "timestamp" in tr.unresolved


@pytest.mark.asyncio
async def test_escalate_returns_original_on_llm_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    ant = _mock_anthropic("not json")
    with patch.dict("sys.modules", {"anthropic": ant}):
        tr = _low_trace()
        result = await escalate([tr], tmp_path)

    assert result[0].confidence == tr.confidence


@pytest.mark.asyncio
async def test_escalate_handles_empty_list(tmp_path: Path) -> None:
    result = await escalate([], tmp_path)
    assert result == []
