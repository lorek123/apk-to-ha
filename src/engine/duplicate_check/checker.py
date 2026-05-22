# SPDX-License-Identifier: MIT
"""P-2.5 — Existing integration detection.

Stage A: package-name match against HA Core component list.
Stage B: BLE service UUID match against the HA Core manifest index.

Both indices are fetched from GitHub and cached locally for one week.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import tomllib
from pathlib import Path

import aiohttp

from ..ir.models import DuplicateCheckResult

_LOGGER = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).parents[3] / ".cache" / "duplicate_check"
_CACHE_TTL = 7 * 24 * 3600  # one week

_HA_TARGET = Path(__file__).parents[3] / "config" / "ha_target.toml"

_HA_CORE_COMPONENTS_URL = (
    "https://api.github.com/repos/home-assistant/core/contents/homeassistant/components"
)

# Semaphore for parallel manifest fetches — avoids hammering GitHub CDN
_MANIFEST_FETCH_SEM = 50

# Known package-name → HA Core domain mappings for common cases
_KNOWN_PACKAGES: dict[str, tuple[str, str]] = {
    "com.tuya": ("core", "tuya"),
    "com.thingclips": ("core", "tuya"),
    "io.shelly": ("core", "shelly"),
    "com.shelly": ("core", "shelly"),
    "io.esphome": ("core", "esphome"),
    "com.espressif": ("core", "esphome"),
}


async def check(
    package_name: str,
    session: aiohttp.ClientSession,
    api_hostnames: list[str] | None = None,
    ble_service_uuids: list[str] | None = None,
) -> DuplicateCheckResult:
    """Run Stage A (package name) + Stage B (BLE service UUID) checks."""

    # Stage A — fast package-name match
    for prefix, (location, name) in _KNOWN_PACKAGES.items():
        if package_name.startswith(prefix):
            _LOGGER.info(
                "Duplicate found via package name: %s → %s/%s",
                package_name, location, name,
            )
            return DuplicateCheckResult(
                found=True,
                location=location,  # type: ignore[arg-type]
                name=name,
                coverage_estimate="full",
            )

    # Stage A extended — fetch HA Core component list and fuzzy-match
    core_components = await _fetch_core_components(session)
    app_label = package_name.split(".")[-1].lower()
    for comp in core_components:
        if comp == app_label or app_label.startswith(comp) or comp.startswith(app_label):
            _LOGGER.info(
                "Possible duplicate in HA Core: %s (app label: %s)", comp, app_label
            )
            return DuplicateCheckResult(
                found=True,
                location="core",
                name=comp,
                coverage_estimate="partial",
            )

    # Stage B — BLE service UUID match
    if ble_service_uuids:
        ble_index = await _fetch_ble_uuid_index(session, core_components)
        for uuid in ble_service_uuids:
            match = ble_index.get(uuid.lower())
            if match:
                _LOGGER.info(
                    "BLE service UUID %s matches HA Core integration: %s",
                    uuid, match["name"],
                )
                return DuplicateCheckResult(
                    found=True,
                    location=match["location"],  # type: ignore[arg-type]
                    name=match["name"],
                    coverage_estimate="full",
                )

    _LOGGER.info("No existing integration found for %s", package_name)
    return DuplicateCheckResult(found=False, coverage_estimate="none")


async def _fetch_core_components(session: aiohttp.ClientSession) -> list[str]:
    cache_file = _CACHE_DIR / "ha_core_components.json"
    if _cache_valid(cache_file):
        return json.loads(cache_file.read_text())

    try:
        async with session.get(
            _HA_CORE_COMPONENTS_URL, timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            resp.raise_for_status()
            data = await resp.json(content_type=None)
            components = [item["name"] for item in data if item.get("type") == "dir"]
    except Exception as exc:
        _LOGGER.warning("Failed to fetch HA Core component list: %s", exc)
        if cache_file.exists():
            return json.loads(cache_file.read_text())
        return []

    _cache_dir_ensure()
    cache_file.write_text(json.dumps(components))
    return components


async def _fetch_ble_uuid_index(
    session: aiohttp.ClientSession,
    core_components: list[str],
) -> dict[str, dict]:
    """Return {service_uuid_lower: {location, name}} from HA Core manifests.

    Fetches raw manifest JSON for all components from github CDN in parallel.
    Cached for one week.
    """
    cache_file = _CACHE_DIR / "ha_core_ble_uuids.json"
    if _cache_valid(cache_file):
        return json.loads(cache_file.read_text())

    try:
        with _HA_TARGET.open("rb") as fh:
            ha_version = tomllib.load(fh)["target"]["ha_core_version"]
    except Exception:
        ha_version = "master"

    base = (
        f"https://raw.githubusercontent.com/home-assistant/core"
        f"/refs/tags/{ha_version}/homeassistant/components"
    )

    sem = asyncio.Semaphore(_MANIFEST_FETCH_SEM)
    index: dict[str, dict] = {}

    async def _fetch_one(name: str) -> None:
        url = f"{base}/{name}/manifest.json"
        async with sem:
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status != 200:
                        return
                    data = await resp.json(content_type=None)
            except Exception:
                return

        for bt_entry in data.get("bluetooth", []):
            uuid = bt_entry.get("service_uuid", "").lower()
            if uuid:
                index[uuid] = {"location": "core", "name": name}
            sd_uuid = bt_entry.get("service_data_uuid", "").lower()
            if sd_uuid:
                index[sd_uuid] = {"location": "core", "name": name}

    await asyncio.gather(*(_fetch_one(c) for c in core_components))

    _cache_dir_ensure()
    cache_file.write_text(json.dumps(index))
    _LOGGER.info("Stage B: indexed %d BLE service UUIDs from HA Core", len(index))
    return index


def _cache_valid(path: Path) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < _CACHE_TTL


def _cache_dir_ensure() -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
