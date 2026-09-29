# SPDX-License-Identifier: MIT
"""Tests for P-2.5 name and brand signals (cases taken from the F-Droid corpus)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from engine.duplicate_check.checker import _brand_counts, _name_match, _tokens

_DOMAINS = [
    "androidtv", "home_connect", "hue", "jellyfin", "light", "mobile_app", "shelly",
    "tasmota", "wake_on_lan", "google",
]  # fmt: skip


@pytest.mark.parametrize(
    ("package", "label", "expected"),
    [
        ("org.jellyfin.mobile", "Jellyfin", "jellyfin"),  # not mobile_app
        ("org.jellyfin.androidtv", "Jellyfin", "jellyfin"),  # not androidtv
        ("dev.jdtech.jellyfin", "Findroid", "jellyfin"),
        ("com.awakeonlanmobile", "AwakeOnLAN", "wake_on_lan"),  # long domain inside a token
        ("io.github.domi04151309.home", "Home", None),  # "home" is generic, not home_connect
        ("kapoue.hestia", "Hestia", None),  # the name alone doesn't say Shelly
        ("com.example.light", "Light", None),  # entity platforms aren't brands
    ],
)
def test_name_match(package: str, label: str, expected: str | None) -> None:
    assert _name_match(_tokens(package, label), _DOMAINS) == expected


def test_brand_counts_whole_words_and_phrases() -> None:
    strings = [
        "Discover Shelly devices on your network",
        "Shelly Plus 1PM",
        "Your Shelly is offline",
        "Send a Wake-on-LAN packet",
        "Sign in with Google",
        "shellyfish",  # not a whole-word mention
        "Turn the light on",
    ]

    counts = _brand_counts(strings, _DOMAINS)

    assert counts["shelly"] == 3
    assert counts["wake_on_lan"] == 1
    assert "google" not in counts  # generic brand, excluded
    assert "light" not in counts  # entity platform, excluded


async def test_system_integrations_are_not_brands(monkeypatch: pytest.MonkeyPatch) -> None:
    from engine.duplicate_check import checker

    async def components(_: object) -> list[str]:
        return ["search", "network", "shelly"]

    async def manifests(_: object, __: object) -> dict[str, dict[str, object]]:
        return {
            "search": {"type": "system", "ble": []},
            "network": {"type": "system", "ble": []},
            "shelly": {"type": "device", "ble": []},
        }

    monkeypatch.setattr(checker, "_fetch_core_components", components)
    monkeypatch.setattr(checker, "_fetch_manifest_index", manifests)
    # Library UI strings say "Search"/"Network" far more often than the app names its product.
    strings = ["Search"] * 12 + ["Network error"] * 6 + ["Add a Shelly device"] * 3

    result = await checker.check(
        "com.pearlnode", MagicMock(), app_label="Pearlnode", app_strings=strings
    )

    assert (result.found, result.name, result.coverage_estimate) == (True, "shelly", "full")


def test_flutter_ui_strings_from_libapp(tmp_path: Path) -> None:
    from engine.extraction.strings_scanner import flutter_ui_strings

    lib = tmp_path / "resources" / "lib" / "arm64-v8a"
    lib.mkdir(parents=True)
    (lib / "libapp.so").write_bytes(b"\x00\x01Connect to your Jellyfin server\x00\xffab\x00")

    assert flutter_ui_strings(tmp_path) == ["Connect to your Jellyfin server"]
    assert flutter_ui_strings(tmp_path / "missing") == []
