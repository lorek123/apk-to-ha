# SPDX-License-Identifier: MIT
"""Tests for Gson/Moshi field-name extraction, including constant references."""

from __future__ import annotations

from pathlib import Path

from engine.extraction.payload_resolver import PayloadResolver, serialized_fields
from engine.extraction.protocol_scanner import ProtocolScanner

_ROBOT = """
package com.example.device;

public class Robot {
    @SerializedName("battery")
    private int battery;

    @SerializedName(RobotApi.MUTE)
    private boolean muted;

    @SerializedName(value = "lcd_l", alternate = {"lcdL"})
    public boolean longLCD;

    @Json(name = RobotApi.FACE)
    private boolean faceDetection;

    @SerializedName(Unknown.CONST)
    private boolean mystery;
}
"""

_CONSTANTS = {"MUTE": "mute", "FACE": "face_detection"}


def test_literals_and_constants_resolve() -> None:
    fields = [(w, t, f) for w, t, f, _ in serialized_fields(_ROBOT, _CONSTANTS)]

    assert ("battery", "int", "battery") in fields
    assert ("mute", "boolean", "muted") in fields
    assert ("lcd_l", "boolean", "longLCD") in fields
    assert ("face_detection", "boolean", "faceDetection") in fields


def test_unresolvable_constant_is_skipped_not_guessed() -> None:
    names = {f for _, _, f, _ in serialized_fields(_ROBOT, _CONSTANTS)}

    assert "mystery" not in names


def test_payload_resolver_uses_constants(tmp_path: Path) -> None:
    src = tmp_path / "sources" / "com" / "example" / "device"
    src.mkdir(parents=True)
    (src / "Robot.java").write_text(_ROBOT)

    schema = PayloadResolver(tmp_path, _CONSTANTS).resolve("Robot")

    assert {f.serialized_name for f in schema.fields} >= {"battery", "mute", "face_detection"}


def test_state_schema_resolves_constants_and_skips_envelope(tmp_path: Path) -> None:
    pkg = tmp_path / "sources" / "com" / "example" / "device"
    pkg.mkdir(parents=True)
    (pkg / "RobotApi.java").write_text(
        "public class RobotApi {\n"
        '    public static final String MUTE = "mute";\n'
        '    public static final String FACE = "face_detection";\n'
        "}\n"
    )
    (pkg / "Robot.java").write_text(_ROBOT)
    (pkg / "RobotBaseResponse.java").write_text(
        "public class RobotBaseResponse {\n"
        '    @SerializedName("cmd")\n    public String cmd;\n'
        '    @SerializedName("seq")\n    public int seq;\n'
        '    @SerializedName("resultCode")\n    public int resultCode;\n'
        "}\n"
    )

    state = ProtocolScanner(tmp_path).scan("com.example.device")[3]
    wire = {f.serialized_name for f in state.fields}

    assert {"mute", "battery"} <= wire
    assert not wire & {"cmd", "seq", "resultCode"}
