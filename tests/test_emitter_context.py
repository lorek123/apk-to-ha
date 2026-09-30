# SPDX-License-Identifier: MIT
"""Tests for the emitter context builder."""

from __future__ import annotations

from typing import Any

import pytest

from engine.emitters.context import _class_prefix, _domain_segment, _slugify, build
from engine.snapshot.harness import load

# ── unit helpers ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "domain,expected",
    [
        ("r2d2", "R2D2"),
        ("my_device", "MyDevice"),
        ("shelly", "Shelly"),
        ("r2d2_hub", "R2D2Hub"),
        ("esphome", "Esphome"),
    ],
)
def test_class_prefix(domain: Any, expected: Any) -> None:
    assert _class_prefix(domain) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("com.bullb.R2-D2", "com_bullb_r2_d2"),
        ("my device", "my_device"),
        ("r2d2", "r2d2"),
    ],
)
def test_slugify(text: Any, expected: Any) -> None:
    assert _slugify(text) == expected


# ── context from snapshot ─────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def r2d2_ctx() -> Any:
    return build(load("bullb_r2d2"))


def test_domain(r2d2_ctx: Any) -> None:
    assert r2d2_ctx["domain"] == "r2d2"


def test_class_prefix_r2d2(r2d2_ctx: Any) -> None:
    assert r2d2_ctx["class_prefix"] == "R2D2"


def test_name_cleaned(r2d2_ctx: Any) -> None:
    # APK stem has version/build suffix stripped
    assert "1.1.31" not in r2d2_ctx["name"]
    assert "R2-D2" in r2d2_ctx["name"]


def test_sdk_package(r2d2_ctx: Any) -> None:
    assert r2d2_ctx["sdk_package"] == "r2d2_sdk"


def test_ws_port(r2d2_ctx: Any) -> None:
    assert r2d2_ctx["ws_port"] == 8887


def test_switches_present(r2d2_ctx: Any) -> None:
    keys = {s["cmd"] for s in r2d2_ctx["switches"]}
    assert "mute" in keys
    assert "power" in keys
    assert "face_detection" in keys
    assert "voice_recognition" in keys
    # connectWifi is NOT a switch (config command, in _NOT_SWITCH)
    assert "connectWifi" not in keys


def test_select_is_mode(r2d2_ctx: Any) -> None:
    assert len(r2d2_ctx["selects"]) == 1
    assert r2d2_ctx["selects"][0]["cmd"] == "mode"
    assert "turn_left" in r2d2_ctx["selects"][0]["options"]


def test_sensors_and_binary_sensors(r2d2_ctx: Any) -> None:
    assert len(r2d2_ctx["sensors"]) > 0
    assert len(r2d2_ctx["binary_sensors"]) > 0
    sensor_keys = {s["key"] for s in r2d2_ctx["sensors"]}
    bin_keys = {s["key"] for s in r2d2_ctx["binary_sensors"]}
    assert "battery" in sensor_keys
    assert "arm" in bin_keys


def test_commands_with_unsuppliable_params_become_actions(r2d2_ctx: Any) -> None:
    # play_sound needs interrupt + sound_id, head-shift needs angle + interrupt:
    # a single number entity can't send either correctly, so they are actions.
    actions = {a["cmd"]: a for a in r2d2_ctx["actions"]}
    assert {f["arg"] for f in actions["play_sound"]["fields"]} == {"interrupt", "sound_id"}
    assert "head-shift" in actions
    assert "move-head" in actions  # a button can't supply "angle"
    assert not r2d2_ctx["numbers"]
    # WebSocket can't return a reply: queries stay unmapped, with the reason.
    unmapped = {u["cmd"]: u["reason"] for u in r2d2_ctx["unmapped_commands"]}
    assert "no reply" in unmapped["getWifiList"]


def test_platforms_follow_mapped_entities(r2d2_ctx: Any) -> None:
    assert "number" not in r2d2_ctx["platforms"]
    assert "binary_sensor" in r2d2_ctx["platforms"]


def test_skip_cmds_not_in_any_entity(r2d2_ctx: Any) -> None:
    all_cmds = (
        {s["cmd"] for s in r2d2_ctx["switches"]}
        | {b["cmd"] for b in r2d2_ctx["buttons"]}
        | {s["cmd"] for s in r2d2_ctx["selects"]}
        | {n["cmd"] for n in r2d2_ctx["numbers"]}
    )
    assert "grantAccess" not in all_cmds
    assert "updBroadcast" not in all_cmds
    assert "gin" not in all_cmds


@pytest.mark.parametrize(
    ("package", "segment"),
    [
        ("dev.inkcast.aos", "inkcast"),
        ("com.example.device.android", "device"),
        ("com.sphero.r2d2", "r2d2"),
        ("app", "app"),
    ],
)
def test_domain_skips_platform_suffixes(package: str, segment: str) -> None:
    assert _domain_segment(package) == segment
