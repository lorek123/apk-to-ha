# SPDX-License-Identifier: MIT
"""Tests for the emitter context builder."""
from __future__ import annotations

import pytest

from engine.emitters.context import build, _class_prefix, _slugify
from engine.snapshot.harness import load


# ── unit helpers ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("domain,expected", [
    ("r2d2", "R2D2"),
    ("my_device", "MyDevice"),
    ("shelly", "Shelly"),
    ("r2d2_hub", "R2D2Hub"),
    ("esphome", "Esphome"),
])
def test_class_prefix(domain, expected):
    assert _class_prefix(domain) == expected


@pytest.mark.parametrize("text,expected", [
    ("com.bullb.R2-D2", "com_bullb_r2_d2"),
    ("my device", "my_device"),
    ("r2d2", "r2d2"),
])
def test_slugify(text, expected):
    assert _slugify(text) == expected


# ── context from snapshot ─────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def r2d2_ctx():
    return build(load("bullb_r2d2"))


def test_domain(r2d2_ctx):
    assert r2d2_ctx["domain"] == "r2d2"


def test_class_prefix_r2d2(r2d2_ctx):
    assert r2d2_ctx["class_prefix"] == "R2D2"


def test_name_cleaned(r2d2_ctx):
    # APK stem has version/build suffix stripped
    assert "1.1.31" not in r2d2_ctx["name"]
    assert "R2-D2" in r2d2_ctx["name"]


def test_sdk_package(r2d2_ctx):
    assert r2d2_ctx["sdk_package"] == "r2d2_sdk"


def test_ws_port(r2d2_ctx):
    assert r2d2_ctx["ws_port"] == 8887


def test_switches_present(r2d2_ctx):
    keys = {s["cmd"] for s in r2d2_ctx["switches"]}
    assert "mute" in keys
    assert "power" in keys
    assert "face_detection" in keys
    assert "voice_recognition" in keys
    # connectWifi is NOT a switch (config command, in _NOT_SWITCH)
    assert "connectWifi" not in keys


def test_select_is_mode(r2d2_ctx):
    assert len(r2d2_ctx["selects"]) == 1
    assert r2d2_ctx["selects"][0]["cmd"] == "mode"
    assert "turn_left" in r2d2_ctx["selects"][0]["options"]


def test_sensors_and_binary_sensors(r2d2_ctx):
    assert len(r2d2_ctx["sensors"]) > 0
    assert len(r2d2_ctx["binary_sensors"]) > 0
    sensor_keys = {s["key"] for s in r2d2_ctx["sensors"]}
    bin_keys = {s["key"] for s in r2d2_ctx["binary_sensors"]}
    assert "battery" in sensor_keys
    assert "arm" in bin_keys


def test_numbers_present(r2d2_ctx):
    keys = {n["cmd"] for n in r2d2_ctx["numbers"]}
    assert "play_sound" in keys
    assert "head-shift" in keys


def test_platforms_include_number(r2d2_ctx):
    assert "number" in r2d2_ctx["platforms"]
    assert "binary_sensor" in r2d2_ctx["platforms"]


def test_skip_cmds_not_in_any_entity(r2d2_ctx):
    all_cmds = (
        {s["cmd"] for s in r2d2_ctx["switches"]}
        | {b["cmd"] for b in r2d2_ctx["buttons"]}
        | {s["cmd"] for s in r2d2_ctx["selects"]}
        | {n["cmd"] for n in r2d2_ctx["numbers"]}
    )
    assert "grantAccess" not in all_cmds
    assert "updBroadcast" not in all_cmds
    assert "gin" not in all_cmds
