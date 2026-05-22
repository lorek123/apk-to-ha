# SPDX-License-Identifier: MIT
"""F-3 — LLM escalation client.

Thin async wrapper around the Anthropic SDK. Returns structured Pydantic objects
from LLM calls, with full structured logging and graceful degradation when
ANTHROPIC_API_KEY is absent or the SDK is not installed.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel

if TYPE_CHECKING:
    pass

_LOGGER = logging.getLogger(__name__)

# Per-model cost estimates (USD per million tokens)
_COST_PER_M: dict[str, tuple[float, float]] = {
    "claude-sonnet-4-6":          (3.0, 15.0),
    "claude-opus-4-7":            (15.0, 75.0),
    "claude-haiku-4-5-20251001":  (0.8, 4.0),
}
_DEFAULT_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 2048
_TEMPERATURE = 0.1
_MAX_RETRIES = 2
_RETRY_BASE_DELAY = 2.0

T = TypeVar("T", bound=BaseModel)


def _sha8(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:8]


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    in_per_m, out_per_m = _COST_PER_M.get(model, (3.0, 15.0))
    return (input_tokens * in_per_m + output_tokens * out_per_m) / 1_000_000


async def call(
    system: str,
    user: str,
    schema_model: type[T],
    model: str = _DEFAULT_MODEL,
) -> T | None:
    """Call the LLM with a structured output contract.

    Returns a validated *schema_model* instance, or None if:
    - ANTHROPIC_API_KEY is not set
    - anthropic package is not installed
    - The LLM response cannot be parsed as valid JSON matching schema_model
    - All retries are exhausted

    Logs every call with prompt hash, response hash, model, token counts,
    latency, and estimated cost.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        _LOGGER.warning("ANTHROPIC_API_KEY not set — LLM escalation skipped")
        return None

    try:
        import anthropic  # noqa: PLC0415 — optional dependency
    except ImportError:
        _LOGGER.warning(
            "anthropic package not installed; run: uv pip install 'hacs-integration-engine[llm]'"
        )
        return None

    schema_json = schema_model.model_json_schema()
    full_system = (
        f"{system}\n\n"
        "Respond ONLY with valid JSON that conforms to this JSON Schema "
        "(no markdown, no explanation):\n\n"
        f"{schema_json}"
    )

    prompt_hash = _sha8(full_system + user)
    client: anthropic.AsyncAnthropic = anthropic.AsyncAnthropic(api_key=api_key)

    for attempt in range(_MAX_RETRIES + 1):
        t0 = time.monotonic()
        try:
            response = await client.messages.create(
                model=model,
                max_tokens=_MAX_TOKENS,
                temperature=_TEMPERATURE,
                system=full_system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.RateLimitError:
            if attempt < _MAX_RETRIES:
                delay = _RETRY_BASE_DELAY * (2 ** attempt)
                _LOGGER.warning(
                    "LLM rate-limited (attempt %d/%d) — sleeping %.0fs",
                    attempt + 1, _MAX_RETRIES + 1, delay,
                )
                await asyncio.sleep(delay)
                continue
            _LOGGER.error("LLM rate-limit exhausted after %d retries", _MAX_RETRIES)
            return None
        except Exception as exc:
            _LOGGER.error("LLM call failed: %s", exc)
            return None

        latency_ms = int((time.monotonic() - t0) * 1000)
        raw = response.content[0].text if response.content else ""
        resp_hash = _sha8(raw)
        input_tok = response.usage.input_tokens
        output_tok = response.usage.output_tokens
        cost = _estimate_cost(model, input_tok, output_tok)

        _LOGGER.info(
            "LLM call: model=%s prompt=%s response=%s "
            "input_tokens=%d output_tokens=%d latency_ms=%d cost_usd=%.4f",
            model, prompt_hash, resp_hash,
            input_tok, output_tok, latency_ms, cost,
        )

        try:
            return schema_model.model_validate_json(raw)
        except Exception as exc:
            _LOGGER.warning("LLM response failed schema validation: %s — raw: %.200s", exc, raw)
            return None

    return None
