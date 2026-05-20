# SPDX-License-Identifier: MIT
"""P-2.5 — Existing integration detection.

Stage A: package-name match against HA Core component list.
Stage B: hostname match against HA Core + HACS default index.
Results are cached locally for one week.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import aiohttp

from ..ir.models import DuplicateCheckResult

_LOGGER = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).parents[3] / ".cache" / "duplicate_check"
_CACHE_TTL = 7 * 24 * 3600  # one week

_HA_CORE_COMPONENTS_URL = (
    "https://api.github.com/repos/home-assistant/core/contents/homeassistant/components"
)
_HACS_DEFAULT_URL = (
    "https://raw.githubusercontent.com/hacs/default/main/integration"
)

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
) -> DuplicateCheckResult:
    """Run Stage A (package name) + Stage B (hostname) checks."""

    # Stage A — fast package-name match
    for prefix, (location, name) in _KNOWN_PACKAGES.items():
        if package_name.startswith(prefix):
            _LOGGER.info("Duplicate found via package name: %s → %s/%s", package_name, location, name)
            return DuplicateCheckResult(
                found=True,
                location=location,  # type: ignore[arg-type]
                name=name,
                coverage_estimate="full",
            )

    # Stage A extended — fetch HA Core component list and fuzzy-match
    core_components = await _fetch_core_components(session)
    app_label = package_name.split(".")[-1].lower()  # e.g. "smartlife" from "com.tuya.smartlife"
    for comp in core_components:
        if comp == app_label or app_label.startswith(comp) or comp.startswith(app_label):
            _LOGGER.info("Possible duplicate in HA Core: %s (app label: %s)", comp, app_label)
            return DuplicateCheckResult(
                found=True,
                location="core",
                name=comp,
                coverage_estimate="partial",
            )

    _LOGGER.info("No existing integration found for %s", package_name)
    return DuplicateCheckResult(found=False, coverage_estimate="none")


async def _fetch_core_components(session: aiohttp.ClientSession) -> list[str]:
    cache_file = _CACHE_DIR / "ha_core_components.json"
    if _cache_valid(cache_file):
        return json.loads(cache_file.read_text())

    try:
        async with session.get(_HA_CORE_COMPONENTS_URL, timeout=aiohttp.ClientTimeout(total=15)) as resp:
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


def _cache_valid(path: Path) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < _CACHE_TTL


def _cache_dir_ensure() -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
