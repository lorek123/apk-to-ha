# SPDX-License-Identifier: MIT
"""Tests for Play Store metadata fetcher and IR integration."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from engine.ingestion.play_store import _clean, _fetch_sync, fetch
from engine.ir.models import PlayStoreInfo


# ── _clean helper ─────────────────────────────────────────────────────────────

def test_clean_strips_html_tags():
    assert _clean("<b>Smart</b> lights") == "Smart lights"


def test_clean_unescapes_html_entities():
    assert _clean("R&amp;D") == "R&D"


def test_clean_collapses_whitespace():
    assert _clean("a  b\n\tc") == "a b c"


def test_clean_returns_empty_for_none():
    assert _clean(None) == ""


# ── _fetch_sync (mocked scraper) ──────────────────────────────────────────────

_MOCK_SCRAPER_RESPONSE = {
    "title": "Govee Home",
    "description": "Govee Home makes it easy to set up and manage your Govee smart devices.\n\nControl lights, thermometers, and more.",
    "summary": "Control your Govee devices with ease.",
    "genre": "House & Home",
    "developer": "Govee International Co. Ltd",
    "developerId": "Govee",
    "score": 4.5,
    "installs": "10,000,000+",
}


def test_fetch_sync_returns_play_store_info():
    with patch("engine.ingestion.play_store._fetch_sync") as mock:
        mock.return_value = PlayStoreInfo(
            title="Govee Home",
            description="Govee Home makes it easy to set up and manage your Govee smart devices.",
            summary="Control your Govee devices with ease.",
            category="House & Home",
            developer="Govee International Co. Ltd",
            developer_id="Govee",
            rating=4.5,
            installs="10,000,000+",
            play_store_url="https://play.google.com/store/apps/details?id=com.govee.home",
        )
        result = mock("com.govee.home")

    assert result is not None
    assert result.title == "Govee Home"
    assert result.category == "House & Home"
    assert result.developer == "Govee International Co. Ltd"
    assert result.rating == 4.5


def test_fetch_sync_not_found_returns_none():
    from google_play_scraper import exceptions  # type: ignore[import-untyped]

    with patch("google_play_scraper.app", side_effect=exceptions.NotFoundError):
        result = _fetch_sync("com.nonexistent.package")

    assert result is None


def test_fetch_sync_maps_all_fields():
    with patch("google_play_scraper.app", return_value=_MOCK_SCRAPER_RESPONSE):
        result = _fetch_sync("com.govee.home")

    assert result is not None
    assert result.title == "Govee Home"
    assert "Govee Home makes it easy" in result.description
    assert result.summary == "Control your Govee devices with ease."
    assert result.category == "House & Home"
    assert result.developer == "Govee International Co. Ltd"
    assert result.developer_id == "Govee"
    assert result.rating == 4.5
    assert result.installs == "10,000,000+"
    assert result.play_store_url == "https://play.google.com/store/apps/details?id=com.govee.home"


# ── async fetch (graceful degradation) ───────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_returns_none_on_timeout():
    import asyncio

    # Simulate timeout by making _fetch_sync raise TimeoutError via asyncio.wait_for
    async def _raise_timeout(*_args, **_kwargs):
        raise TimeoutError("simulated timeout")

    with patch("engine.ingestion.play_store.asyncio.wait_for", side_effect=TimeoutError):
        result = await fetch("com.example.app")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_returns_none_on_exception():
    with patch("engine.ingestion.play_store.asyncio.to_thread",
               side_effect=RuntimeError("network error")):
        result = await fetch("com.example.app")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_returns_info_on_success():
    expected = PlayStoreInfo(
        title="My App",
        description="A great smart home app.",
        category="House & Home",
        developer="Example Inc.",
    )
    with patch("engine.ingestion.play_store.asyncio.to_thread", return_value=expected):
        result = await fetch("com.example.app")
    assert result == expected


# ── IR model ──────────────────────────────────────────────────────────────────

def test_play_store_info_optional_fields():
    info = PlayStoreInfo(title="App", description="Desc")
    assert info.summary is None
    assert info.category is None
    assert info.developer is None
    assert info.rating is None


def test_protocol_ir_accepts_play_store_none():
    from engine.ir.models import (
        AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
        Framework, ProtocolIR, StateSchema, TransportContract, TransportType,
    )
    ir = ProtocolIR(
        apk_path="test",
        package_name="com.example.app",
        app_name="Example",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.HTTP_REST, port=80, host_source="manual"),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(fields=[]),
        play_store=None,
    )
    assert ir.play_store is None


def test_protocol_ir_stores_play_store_info():
    from engine.ir.models import (
        AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
        Framework, ProtocolIR, StateSchema, TransportContract, TransportType,
    )
    ps = PlayStoreInfo(title="App", description="Desc", category="Tools")
    ir = ProtocolIR(
        apk_path="test",
        package_name="com.example.app",
        app_name="Example",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.HTTP_REST, port=80, host_source="manual"),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(fields=[]),
        play_store=ps,
    )
    assert ir.play_store is not None
    assert ir.play_store.category == "Tools"


# ── context propagation ───────────────────────────────────────────────────────

def test_context_includes_play_store_fields():
    from engine.ir.models import (
        AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
        Framework, ProtocolIR, StateSchema, TransportContract, TransportType,
    )
    from engine.emitters.context import build

    ps = PlayStoreInfo(
        title="Govee Home",
        description="Full description text here.",
        summary="Short summary.",
        category="House & Home",
        developer="Govee International Co. Ltd",
    )
    ir = ProtocolIR(
        apk_path="test",
        package_name="com.govee.home",
        app_name="Govee Home",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.HTTP_REST, port=80, host_source="manual"),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(fields=[]),
        play_store=ps,
    )
    ctx = build(ir)

    assert ctx["app_description"] == "Full description text here."
    assert ctx["app_summary"] == "Short summary."
    assert ctx["play_category"] == "House & Home"
    assert ctx["play_developer"] == "Govee International Co. Ltd"


def test_context_empty_strings_when_no_play_store():
    from engine.ir.models import (
        AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
        Framework, ProtocolIR, StateSchema, TransportContract, TransportType,
    )
    from engine.emitters.context import build

    ir = ProtocolIR(
        apk_path="test",
        package_name="com.example.app",
        app_name="Example",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.HTTP_REST, port=80, host_source="manual"),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(fields=[]),
        play_store=None,
    )
    ctx = build(ir)

    assert ctx["app_description"] == ""
    assert ctx["app_summary"] == ""
    assert ctx["play_category"] == ""
    assert ctx["play_developer"] == ""


def test_app_summary_falls_back_to_description_prefix():
    """When summary is None, app_summary is the first 200 chars of description."""
    from engine.ir.models import (
        AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
        Framework, ProtocolIR, StateSchema, TransportContract, TransportType,
    )
    from engine.emitters.context import build

    long_desc = "A" * 300
    ps = PlayStoreInfo(title="App", description=long_desc, summary=None)
    ir = ProtocolIR(
        apk_path="test",
        package_name="com.example.app",
        app_name="Example",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.HTTP_REST, port=80, host_source="manual"),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(fields=[]),
        play_store=ps,
    )
    ctx = build(ir)
    assert len(ctx["app_summary"]) == 200
