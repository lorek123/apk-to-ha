# SPDX-License-Identifier: MIT
"""Tests for P1-1 JadxClient — typed async wrapper around the JADX plugin HTTP API."""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.ingestion.jadx_client import JadxClient


# ── helpers ────────────────────────────────────────────────────────────────────

def _mock_session(response_map: dict[str, Any]) -> MagicMock:
    """Build a mock aiohttp.ClientSession whose GET responses come from response_map.

    response_map keys are endpoint substrings (e.g. "health", "class-source").
    Each value is either a dict (returned as JSON) or an Exception (raised).
    """
    def _make_resp(payload: Any) -> MagicMock:
        if isinstance(payload, Exception):
            raise payload
        resp = MagicMock()
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=None)
        resp.raise_for_status = MagicMock()
        resp.json = AsyncMock(return_value=payload)
        return resp

    session = MagicMock()

    def _get(url: str, **_kwargs: Any) -> MagicMock:
        for key, val in response_map.items():
            if key in url:
                return _make_resp(val)
        return _make_resp({})

    session.get = MagicMock(side_effect=_get)
    session.close = AsyncMock()
    return session


async def _client_with(responses: dict[str, Any]) -> JadxClient:
    """Return an already-entered JadxClient backed by mocked responses."""
    client = JadxClient()
    client._session = _mock_session(responses)
    return client


# ── is_available ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_available_true_on_health_response() -> None:
    client = await _client_with({"health": {"status": "ok"}})
    assert await client.is_available() is True


@pytest.mark.asyncio
async def test_is_available_false_on_empty_response() -> None:
    client = await _client_with({"health": {}})
    assert await client.is_available() is False


@pytest.mark.asyncio
async def test_is_available_false_on_error_key() -> None:
    client = await _client_with({"health": {"error": "not running"}})
    assert await client.is_available() is False


@pytest.mark.asyncio
async def test_is_available_false_on_connection_error() -> None:
    client = JadxClient()
    client._session = _mock_session({"health": ConnectionRefusedError("refused")})
    assert await client.is_available() is False


# ── get_all_classes ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_all_classes_returns_list() -> None:
    client = await _client_with({
        "all-classes": {"classes": ["com.example.Foo", "com.example.Bar"]}
    })
    result = await client.get_all_classes()
    assert result == ["com.example.Foo", "com.example.Bar"]


@pytest.mark.asyncio
async def test_get_all_classes_empty_on_missing_key() -> None:
    client = await _client_with({"all-classes": {"other": []}})
    assert await client.get_all_classes() == []


@pytest.mark.asyncio
async def test_get_all_classes_passes_pagination_params() -> None:
    session = _mock_session({"all-classes": {"classes": []}})
    client = JadxClient()
    client._session = session
    await client.get_all_classes(offset=10, count=50)
    call_kwargs = session.get.call_args
    assert call_kwargs is not None
    params = call_kwargs.kwargs.get("params") or call_kwargs.args[1] if len(call_kwargs.args) > 1 else {}
    # params may be in kwargs
    params = session.get.call_args.kwargs.get("params", {})
    assert params.get("offset") == 10
    assert params.get("count") == 50


# ── get_class_source ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_class_source_returns_source() -> None:
    src = "public class Foo { }"
    client = await _client_with({"class-source": {"source": src}})
    result = await client.get_class_source("com.example.Foo")
    assert result == src


@pytest.mark.asyncio
async def test_get_class_source_accepts_code_key() -> None:
    src = "public class Bar { }"
    client = await _client_with({"class-source": {"code": src}})
    assert await client.get_class_source("com.example.Bar") == src


@pytest.mark.asyncio
async def test_get_class_source_returns_none_when_not_found() -> None:
    client = await _client_with({"class-source": {}})
    assert await client.get_class_source("com.example.Missing") is None


@pytest.mark.asyncio
async def test_get_class_source_returns_none_on_network_error() -> None:
    client = JadxClient()
    client._session = _mock_session({"class-source": OSError("refused")})
    assert await client.get_class_source("com.example.X") is None


# ── get_methods_of_class ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_methods_of_class_returns_list() -> None:
    client = await _client_with({
        "methods-of-class": {"methods": ["foo()", "bar(int)"]}
    })
    assert await client.get_methods_of_class("com.example.Cls") == ["foo()", "bar(int)"]


@pytest.mark.asyncio
async def test_get_methods_of_class_empty_on_no_methods_key() -> None:
    client = await _client_with({"methods-of-class": {}})
    assert await client.get_methods_of_class("com.example.Cls") == []


# ── get_fields_of_class ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_fields_of_class_returns_list_of_dicts() -> None:
    fields = [{"name": "mPort", "type": "int"}, {"name": "mHost", "type": "String"}]
    client = await _client_with({"fields-of-class": {"fields": fields}})
    result = await client.get_fields_of_class("com.example.Client")
    assert len(result) == 2
    assert result[0]["name"] == "mPort"


# ── get_method_by_name ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_method_by_name_returns_dict() -> None:
    payload = {"class_name": "com.example.Client", "method_name": "connect", "source": "void connect(){}"}
    client = await _client_with({"method-by-name": payload})
    result = await client.get_method_by_name("com.example.Client", "connect")
    assert result is not None
    assert result["method_name"] == "connect"


@pytest.mark.asyncio
async def test_get_method_by_name_returns_none_on_error() -> None:
    client = await _client_with({"method-by-name": {"error": "not found"}})
    assert await client.get_method_by_name("com.example.X", "missing") is None


@pytest.mark.asyncio
async def test_get_method_by_name_returns_none_on_empty() -> None:
    client = await _client_with({"method-by-name": {}})
    assert await client.get_method_by_name("com.example.X", "missing") is None


# ── search_classes_by_keyword ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_search_classes_by_keyword_returns_list() -> None:
    client = await _client_with({
        "search-classes-by-keyword": {"classes": ["com.example.WsClient"]}
    })
    result = await client.search_classes_by_keyword("WebSocket")
    assert "com.example.WsClient" in result


@pytest.mark.asyncio
async def test_search_classes_by_keyword_accepts_results_key() -> None:
    client = await _client_with({
        "search-classes-by-keyword": {"results": ["com.example.AuthManager"]}
    })
    result = await client.search_classes_by_keyword("grantAccess")
    assert "com.example.AuthManager" in result


@pytest.mark.asyncio
async def test_search_classes_by_keyword_empty_on_unavailable() -> None:
    client = JadxClient()
    client._session = _mock_session({"search-classes-by-keyword": ConnectionError()})
    assert await client.search_classes_by_keyword("anything") == []


# ── search_method_by_name ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_search_method_by_name_returns_list() -> None:
    methods = [{"class_name": "com.example.Signer", "method_name": "sign"}]
    client = await _client_with({"search-method": {"methods": methods}})
    result = await client.search_method_by_name("sign")
    assert len(result) == 1
    assert result[0]["method_name"] == "sign"


# ── get_android_manifest ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_android_manifest_returns_xml() -> None:
    xml = '<manifest package="com.example.app"></manifest>'
    client = await _client_with({"manifest": {"content": xml}})
    assert await client.get_android_manifest() == xml


@pytest.mark.asyncio
async def test_get_android_manifest_returns_none_on_empty() -> None:
    client = await _client_with({"manifest": {}})
    assert await client.get_android_manifest() is None


# ── get_strings ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_strings_returns_list() -> None:
    strings = [{"name": "app_name", "value": "R2-D2"}, {"name": "error_msg", "value": "Connection failed"}]
    client = await _client_with({"strings": {"strings": strings}})
    result = await client.get_strings()
    assert len(result) == 2
    assert result[0]["name"] == "app_name"


# ── cross-references ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_xrefs_to_class_returns_references() -> None:
    refs = [{"class_name": "com.example.Client", "method_name": "init", "line": 42}]
    client = await _client_with({"xrefs-to-class": {"references": refs}})
    result = await client.get_xrefs_to_class("com.example.WsClient")
    assert len(result) == 1
    assert result[0]["line"] == 42


@pytest.mark.asyncio
async def test_get_xrefs_to_method_returns_references() -> None:
    refs = [{"class_name": "com.example.Activity", "method_name": "onCreate"}]
    client = await _client_with({"xrefs-to-method": {"references": refs}})
    result = await client.get_xrefs_to_method("com.example.Signer", "sign")
    assert len(result) == 1


@pytest.mark.asyncio
async def test_get_xrefs_to_field_returns_references() -> None:
    refs = [{"class_name": "com.example.Config", "field_name": "apiKey"}]
    client = await _client_with({"xrefs-to-field": {"references": refs}})
    result = await client.get_xrefs_to_field("com.example.Config", "apiKey")
    assert len(result) == 1


@pytest.mark.asyncio
async def test_xrefs_empty_on_network_error() -> None:
    client = JadxClient()
    client._session = _mock_session({"xrefs-to-class": TimeoutError()})
    assert await client.get_xrefs_to_class("com.example.X") == []


# ── get_smali ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_smali_returns_content() -> None:
    smali = ".class public Lcom/example/Foo;\n.super Ljava/lang/Object;"
    client = await _client_with({"smali-of-class": {"smali": smali}})
    assert await client.get_smali("com.example.Foo") == smali


@pytest.mark.asyncio
async def test_get_smali_returns_none_on_empty() -> None:
    client = await _client_with({"smali-of-class": {}})
    assert await client.get_smali("com.example.Foo") is None


# ── context manager lifecycle ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_context_manager_creates_and_closes_session() -> None:
    mock_session = MagicMock()
    mock_session.close = AsyncMock()
    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with JadxClient() as client:
            assert client._session is mock_session
        mock_session.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_context_manager_clears_session_after_exit() -> None:
    mock_session = MagicMock()
    mock_session.close = AsyncMock()
    with patch("aiohttp.ClientSession", return_value=mock_session):
        async with JadxClient() as client:
            pass
        assert client._session is None


# ── custom host / port ─────────────────────────────────────────────────────────

def test_custom_host_port_sets_base_url() -> None:
    client = JadxClient(host="192.168.1.5", port=9000)
    assert "192.168.1.5" in client._base
    assert "9000" in client._base
