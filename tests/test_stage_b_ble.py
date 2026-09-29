# SPDX-License-Identifier: MIT
"""Tests for Stage B: BLE service UUID duplicate detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.duplicate_check.checker import _fetch_ble_uuid_index, _ha_ref, check

# ── helpers ────────────────────────────────────────────────────────────────────


def _resp(status: int, data: dict[str, Any] | list[Any] | None = None) -> MagicMock:
    """Build a synchronous async-context-manager mock for one aiohttp response."""
    r = MagicMock()
    r.status = status
    r.json = AsyncMock(return_value=data or {})
    r.raise_for_status = MagicMock(
        side_effect=None if status < 400 else Exception(f"HTTP {status}")
    )
    r.__aenter__ = AsyncMock(return_value=r)
    r.__aexit__ = AsyncMock(return_value=False)
    return r


def _mock_session(manifest_map: dict[str, dict[str, Any]]) -> MagicMock:
    """Return an aiohttp.ClientSession mock that serves manifests from manifest_map.

    manifest_map: {component_name: manifest_dict}
    session.get(url) returns a synchronous async-context-manager mock.
    """
    session = MagicMock()

    def _get(url: str, **kwargs: object) -> MagicMock:
        for name, data in manifest_map.items():
            if f"/components/{name}/manifest.json" in url:
                return _resp(200, data)
        return _resp(404)

    session.get = _get
    return session


def _mock_components_session(
    components: list[str],
    manifest_map: dict[str, dict[str, Any]],
) -> MagicMock:
    """Session that serves both the component listing AND per-manifest calls."""
    session = MagicMock()

    def _get(url: str, **kwargs: object) -> MagicMock:
        # Component list: contents/homeassistant → components tree sha → git tree
        if "api.github.com" in url and url.endswith("contents/homeassistant"):
            return _resp(200, [{"name": "components", "sha": "tree123", "type": "dir"}])
        if "api.github.com" in url and url.endswith("git/trees/tree123"):
            tree = [{"path": c, "type": "tree"} for c in components]
            return _resp(200, {"tree": tree, "truncated": False})

        for name, data in manifest_map.items():
            if f"/components/{name}/manifest.json" in url:
                return _resp(200, data)

        return _resp(404)

    session.get = _get
    return session


# ── _fetch_ble_uuid_index unit tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_ble_uuid_index_extracts_service_uuid(tmp_path: Path) -> None:
    session = _mock_session(
        {
            "switchbot": {
                "domain": "switchbot",
                "bluetooth": [{"service_uuid": "0000cba2-0000-1000-8000-00805f9b34fb"}],
            }
        }
    )
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await _fetch_ble_uuid_index(session, ["switchbot", "other"])
    assert "0000cba2-0000-1000-8000-00805f9b34fb" in result
    assert result["0000cba2-0000-1000-8000-00805f9b34fb"]["name"] == "switchbot"
    assert result["0000cba2-0000-1000-8000-00805f9b34fb"]["location"] == "core"


@pytest.mark.asyncio
async def test_ble_uuid_index_extracts_service_data_uuid(tmp_path: Path) -> None:
    session = _mock_session(
        {
            "govee_ble": {
                "domain": "govee_ble",
                "bluetooth": [{"service_data_uuid": "0000ec88-0000-1000-8000-00805f9b34fb"}],
            }
        }
    )
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await _fetch_ble_uuid_index(session, ["govee_ble"])
    assert "0000ec88-0000-1000-8000-00805f9b34fb" in result


@pytest.mark.asyncio
async def test_ble_uuid_index_normalises_to_lowercase(tmp_path: Path) -> None:
    session = _mock_session(
        {
            "mydevice": {
                "domain": "mydevice",
                "bluetooth": [{"service_uuid": "0000CBA2-0000-1000-8000-00805F9B34FB"}],
            }
        }
    )
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await _fetch_ble_uuid_index(session, ["mydevice"])
    assert "0000cba2-0000-1000-8000-00805f9b34fb" in result


@pytest.mark.asyncio
async def test_ble_uuid_index_skips_non_bluetooth_manifests(tmp_path: Path) -> None:
    session = _mock_session(
        {
            "shelly": {"domain": "shelly", "iot_class": "local_polling"},
        }
    )
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await _fetch_ble_uuid_index(session, ["shelly"])
    assert result == {}


@pytest.mark.asyncio
async def test_ble_uuid_index_uses_cache(tmp_path: Path) -> None:
    cached = {"0000abcd-0000-1000-8000-00805f9b34fb": {"location": "core", "name": "cached"}}
    cache_file = tmp_path / f"ha_core_ble_uuids-{_ha_ref()}.json"
    cache_file.write_text(json.dumps(cached))
    session = MagicMock()  # should NOT be called
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await _fetch_ble_uuid_index(session, ["any"])
    assert result == cached
    session.get.assert_not_called()


@pytest.mark.asyncio
async def test_ble_uuid_index_returns_empty_on_all_404(tmp_path: Path) -> None:
    session = _mock_session({})  # all 404
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await _fetch_ble_uuid_index(session, ["unknown_comp"])
    assert result == {}


# ── check() Stage B integration tests ────────────────────────────────────────


@pytest.mark.asyncio
async def test_check_stage_b_matches_ble_service_uuid(tmp_path: Path) -> None:
    switchbot_uuid = "0000cba2-0000-1000-8000-00805f9b34fb"
    session = _mock_components_session(
        components=["switchbot"],
        manifest_map={
            "switchbot": {
                "domain": "switchbot",
                "bluetooth": [{"service_uuid": switchbot_uuid}],
            }
        },
    )
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await check(
            "com.unknown.device",
            session,
            ble_service_uuids=[switchbot_uuid],
        )
    assert result.found is True
    assert result.name == "switchbot"
    assert result.location == "core"
    assert result.coverage_estimate == "full"


@pytest.mark.asyncio
async def test_check_stage_b_no_match_returns_not_found(tmp_path: Path) -> None:
    session = _mock_components_session(
        components=["switchbot"],
        manifest_map={
            "switchbot": {
                "domain": "switchbot",
                "bluetooth": [{"service_uuid": "0000cba2-0000-1000-8000-00805f9b34fb"}],
            }
        },
    )
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await check(
            "com.unknown.device",
            session,
            ble_service_uuids=["0000ffff-0000-1000-8000-00805f9b34fb"],
        )
    assert result.found is False
    assert result.coverage_estimate == "none"


@pytest.mark.asyncio
async def test_check_stage_b_skipped_when_no_ble_uuids(tmp_path: Path) -> None:
    """Stage B is not called when ble_service_uuids is None."""
    session = _mock_components_session(components=[], manifest_map={})
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await check("com.totally.new.device", session, ble_service_uuids=None)
    assert result.found is False


@pytest.mark.asyncio
async def test_check_stage_a_still_takes_priority(tmp_path: Path) -> None:
    """Known package names short-circuit before Stage B."""
    session = _mock_components_session(components=[], manifest_map={})
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        result = await check(
            "com.tuya.smartlife",
            session,
            ble_service_uuids=["0000ffff-0000-1000-8000-00805f9b34fb"],
        )
    assert result.found is True
    assert result.name == "tuya"


@pytest.mark.asyncio
async def test_ble_uuid_index_written_to_cache(tmp_path: Path) -> None:
    session = _mock_session(
        {
            "mydev": {
                "domain": "mydev",
                "bluetooth": [{"service_uuid": "0000aaaa-0000-1000-8000-00805f9b34fb"}],
            }
        }
    )
    with patch("engine.duplicate_check.checker._CACHE_DIR", tmp_path):
        await _fetch_ble_uuid_index(session, ["mydev"])
    cache_file = tmp_path / f"ha_core_ble_uuids-{_ha_ref()}.json"
    assert cache_file.exists()
    cached = json.loads(cache_file.read_text())
    assert "0000aaaa-0000-1000-8000-00805f9b34fb" in cached
