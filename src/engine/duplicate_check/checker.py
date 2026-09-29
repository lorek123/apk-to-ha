# SPDX-License-Identifier: MIT
"""P-2.5 — Existing integration detection.

Signals, strongest first:
  1. Known package prefixes (vendor SDKs, HA's own companion app).
  2. Name: package segments + the app's label. A distinctive token equal to an
     HA Core domain (org.jellyfin.mobile → jellyfin), or containing a long one
     (awakeonlanmobile ⊃ wake_on_lan), is full coverage.
  3. Brands: HA Core domains named in the app's own strings.xml. One dominant
     brand (a Shelly controller) is full coverage; several (a multi-vendor
     app) is partial.
  4. BLE service UUIDs matched against HA Core manifests.

The component list comes from the git trees API at the pinned HA tag: the
contents API caps directory listings at 1000 entries (HA Core has ~1500).
Indices are cached per HA version for one week.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import tomllib
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

import aiohttp

from ..ir.models import DuplicateCheckResult

_LOGGER = logging.getLogger(__name__)

_CACHE_DIR = Path(__file__).parents[3] / ".cache" / "duplicate_check"
_CACHE_TTL = 7 * 24 * 3600  # one week

_HA_TARGET = Path(__file__).parents[3] / "config" / "ha_target.toml"

_GITHUB_API = "https://api.github.com/repos/home-assistant/core"

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
    "io.homeassistant": ("core", "mobile_app"),  # HA's own companion app
}

# Name tokens that say nothing about which product an app is for.
_GENERIC_TOKENS = frozenset(
    {
        "android", "androidtv", "app", "apps", "beta", "client", "com", "companion",
        "control", "controller", "debug", "dev", "free", "github", "gitlab", "home",
        "lite", "media", "minimal", "mobile", "music", "net", "official", "org",
        "player", "pro", "release", "remote", "smart", "wear",
    }
)  # fmt: skip

# Core domains that are entity platforms / HA internals or big generic brands:
# an app mentioning "light" or "Google" says nothing about duplicating them.
# "github", "browser" and "version" are product integrations, but nearly every
# FOSS app names them on its about/settings pages ("report issues on GitHub").
_NON_BRAND_DOMAINS = frozenset(
    {
        "air_quality", "alarm_control_panel", "api", "application_credentials", "assist",
        "browser", "github", "version",
        "binary_sensor", "button", "calendar", "camera", "climate", "cloud", "config",
        "conversation", "counter", "cover", "date", "datetime", "default_config",
        "device_tracker", "event", "fan", "frontend", "google", "homeassistant", "http",
        "humidifier", "image", "input_boolean", "lawn_mower", "light", "lock",
        "media_player", "media_source", "mobile_app", "notify", "number", "remote",
        "scene", "schedule", "script", "select", "sensor", "siren", "stt", "switch",
        "system_health", "text", "time", "todo", "tts", "update", "vacuum", "valve",
        "wake_word", "water_heater", "weather", "webhook", "websocket_api", "zone",
    }
)  # fmt: skip

# integration_type values that stand for a product a user owns or subscribes to.
_PRODUCT_TYPES = frozenset({"hub", "device", "service"})

# Long normalised domains may match inside a token (awakeonlanmobile ⊃ wakeonlan).
_MIN_SUBSTRING_DOMAIN = 8
_URL = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)
_MIN_SENTENCE_WORDS = 3
# Brand signal: a domain needs this many mentions, and must lead the runner-up
# by this factor, to count as the app's product.
_MIN_BRAND_MENTIONS = 3
_BRAND_DOMINANCE = 2


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _tokens(package_name: str, app_label: str | None) -> set[str]:
    words = package_name.split(".") + re.split(r"[\s\-_.]+", app_label or "")
    return {t for t in map(_norm, words) if len(t) >= 4 and t not in _GENERIC_TOKENS}


def _name_match(tokens: set[str], domains: Iterable[str]) -> str | None:
    by_norm = {_norm(d): d for d in domains if d not in _NON_BRAND_DOMAINS}
    for token in sorted(tokens):
        if token in by_norm:
            return by_norm[token]
    for token in sorted(tokens):
        for dnorm, domain in by_norm.items():
            if len(dnorm) >= _MIN_SUBSTRING_DOMAIN and dnorm in token:
                return domain
    return None


def _brand_counts(app_strings: Iterable[str], domains: Iterable[str]) -> Counter[str]:
    """Mentions of each domain in natural-language strings.

    Only strings of 3+ words count, with URLs removed: an app names its product
    in sentences ("connect to your Jellyfin server"), while noise comes from
    data tables (country lists: "Aruba") and links (github.com/...).
    """
    sentences = (_URL.sub(" ", s) for s in app_strings)
    text = " \n ".join(s for s in sentences if len(s.split()) >= _MIN_SENTENCE_WORDS).lower()
    counts: Counter[str] = Counter()
    for domain in domains:
        if domain in _NON_BRAND_DOMAINS or len(_norm(domain)) < 5:
            continue
        phrase = r"[ _\-]?".join(map(re.escape, domain.split("_")))
        n = len(re.findall(rf"\b{phrase}\b", text))
        if n:
            counts[domain] = n
    return counts


def _found(name: str, coverage: str, why: str) -> DuplicateCheckResult:
    _LOGGER.info("Duplicate (%s): core/%s — %s", coverage, name, why)
    return DuplicateCheckResult(
        found=True,
        location="core",
        name=name,
        coverage_estimate="full" if coverage == "full" else "partial",
    )


async def check(
    package_name: str,
    session: aiohttp.ClientSession,
    api_hostnames: list[str] | None = None,
    ble_service_uuids: list[str] | None = None,
    app_label: str | None = None,
    app_strings: list[str] | None = None,
) -> DuplicateCheckResult:
    """Decide whether HA already covers this app's device (see module docstring)."""
    for prefix, (location, name) in _KNOWN_PACKAGES.items():
        if package_name.startswith(prefix):
            _LOGGER.info("Duplicate via known package %s → %s/%s", prefix, location, name)
            return DuplicateCheckResult(
                found=True, location=location, name=name, coverage_estimate="full"
            )

    core_components = await _fetch_core_components(session)

    domain = _name_match(_tokens(package_name, app_label), core_components)
    if domain:
        return _found(domain, "full", f"name ({package_name}, label {app_label!r})")

    brands: list[tuple[str, int]] = []
    if app_strings:
        products = await _product_domains(session, core_components)
        brands = _brand_counts(app_strings, sorted(products)).most_common(2)
    if brands and brands[0][1] >= _MIN_BRAND_MENTIONS:
        (top, n), runner_up = brands[0], (brands[1][1] if len(brands) > 1 else 0)
        dominant = n >= _BRAND_DOMINANCE * runner_up
        return _found(top, "full" if dominant else "partial", f"strings mention it {n}x")

    # BLE service UUID match
    if ble_service_uuids:
        ble_index = await _fetch_ble_uuid_index(session, core_components)
        for uuid in ble_service_uuids:
            match = ble_index.get(uuid.lower())
            if match:
                _LOGGER.info(
                    "BLE service UUID %s matches HA Core integration: %s",
                    uuid,
                    match["name"],
                )
                return DuplicateCheckResult(
                    found=True,
                    location=match["location"],
                    name=match["name"],
                    coverage_estimate="full",
                )

    _LOGGER.info("No existing integration found for %s", package_name)
    return DuplicateCheckResult(found=False, coverage_estimate="none")


def _ha_ref() -> str:
    try:
        with _HA_TARGET.open("rb") as fh:
            return str(tomllib.load(fh)["target"]["ha_core_version"])
    except OSError, KeyError, tomllib.TOMLDecodeError:
        return "dev"


async def _fetch_core_components(session: aiohttp.ClientSession) -> list[str]:
    ref = _ha_ref()
    cache_file = _CACHE_DIR / f"ha_core_components-{ref}.json"
    if _cache_valid(cache_file):
        return cast(list[str], json.loads(cache_file.read_text()))

    timeout = aiohttp.ClientTimeout(total=30)
    try:
        # contents/ caps listings at 1000 entries; the git tree of the directory doesn't.
        async with session.get(
            f"{_GITHUB_API}/contents/homeassistant", params={"ref": ref}, timeout=timeout
        ) as resp:
            resp.raise_for_status()
            listing = await resp.json(content_type=None)
        tree_sha = next(i["sha"] for i in listing if i["name"] == "components")
        async with session.get(f"{_GITHUB_API}/git/trees/{tree_sha}", timeout=timeout) as resp:
            resp.raise_for_status()
            tree = await resp.json(content_type=None)
        components = sorted(e["path"] for e in tree["tree"] if e["type"] == "tree")
        if tree.get("truncated"):
            _LOGGER.warning("HA Core component tree truncated at %d entries", len(components))
    except Exception as exc:
        _LOGGER.warning("Failed to fetch HA Core component list: %s", exc)
        if cache_file.exists():
            return cast(list[str], json.loads(cache_file.read_text()))
        return []

    _cache_dir_ensure()
    cache_file.write_text(json.dumps(components))
    return components


async def _fetch_manifest_index(
    session: aiohttp.ClientSession, core_components: list[str]
) -> dict[str, dict[str, Any]]:
    """{domain: {"type": integration_type, "ble": [service uuids]}} from HA Core manifests.

    Fetches every component's manifest.json from the GitHub CDN at the pinned tag,
    in parallel. Cached per HA version for one week.
    """
    cache_file = _CACHE_DIR / f"ha_core_manifests-{_ha_ref()}.json"
    if _cache_valid(cache_file):
        return cast(dict[str, dict[str, Any]], json.loads(cache_file.read_text()))

    base = (
        f"https://raw.githubusercontent.com/home-assistant/core"
        f"/refs/tags/{_ha_ref()}/homeassistant/components"
    )
    sem = asyncio.Semaphore(_MANIFEST_FETCH_SEM)
    index: dict[str, dict[str, Any]] = {}

    async def _fetch_one(name: str) -> None:
        url = f"{base}/{name}/manifest.json"
        async with sem:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status != 200:
                        return
                    data = await resp.json(content_type=None)
            except Exception:
                return
        uuids = [
            u.lower()
            for entry in data.get("bluetooth", [])
            for u in (entry.get("service_uuid"), entry.get("service_data_uuid"))
            if u
        ]
        # HA's default integration_type when a manifest omits it is "hub".
        index[name] = {"type": data.get("integration_type", "hub"), "ble": uuids}

    await asyncio.gather(*(_fetch_one(c) for c in core_components))

    if index:
        _cache_dir_ensure()
        cache_file.write_text(json.dumps(index))
    return index


async def _fetch_ble_uuid_index(
    session: aiohttp.ClientSession,
    core_components: list[str],
) -> dict[str, dict[str, str]]:
    """Return {service_uuid_lower: {location, name}} from HA Core manifests."""
    cache_file = _CACHE_DIR / f"ha_core_ble_uuids-{_ha_ref()}.json"
    if _cache_valid(cache_file):
        return cast(dict[str, dict[str, str]], json.loads(cache_file.read_text()))

    manifests = await _fetch_manifest_index(session, core_components)
    index = {
        uuid: {"location": "core", "name": name}
        for name, info in manifests.items()
        for uuid in info["ble"]
    }
    _cache_dir_ensure()
    cache_file.write_text(json.dumps(index))
    _LOGGER.info("Stage B: indexed %d BLE service UUIDs from HA Core", len(index))
    return index


async def _product_domains(session: aiohttp.ClientSession, core_components: list[str]) -> set[str]:
    """Domains that integrate a product (hub/device/service), not HA internals.

    Keeps brand matching off everyday words that happen to be system
    integrations ("search", "network", "power"). If manifests can't be fetched,
    fall back to the static non-brand list only.
    """
    manifests = await _fetch_manifest_index(session, core_components)
    if not manifests:
        return set(core_components)
    return {d for d, info in manifests.items() if info["type"] in _PRODUCT_TYPES}


def _cache_valid(path: Path) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < _CACHE_TTL


def _cache_dir_ensure() -> None:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
