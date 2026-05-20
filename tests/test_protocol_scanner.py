# SPDX-License-Identifier: MIT
"""Tests for the protocol scanner — constant resolution, command lists, events."""
from __future__ import annotations

from pathlib import Path

import pytest

from engine.extraction.protocol_scanner import ProtocolScanner
from engine.ir.models import Direction, TransportType


def _make_sources(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write java source files into tmp_path/sources/com/test/ and return apk_out_dir."""
    pkg = tmp_path / "sources" / "com" / "test"
    pkg.mkdir(parents=True)
    for name, content in files.items():
        (pkg / name).write_text(content)
    return tmp_path


# ── constant resolution ───────────────────────────────────────────────────────

def test_collect_str_constants(tmp_path):
    src = _make_sources(tmp_path, {"Api.java": """
        public static final String MUTE = "mute";
        private static final String GRANT = "grantAccess";
    """})
    scanner = ProtocolScanner(src)
    scanner._app_sources = list((src / "sources").rglob("*.java"))
    scanner._collect_str_constants()
    assert scanner._str_constants["MUTE"] == "mute"
    assert scanner._str_constants["GRANT"] == "grantAccess"


def test_collect_cmd_lists(tmp_path):
    src = _make_sources(tmp_path, {"Api.java": """
        public static final String MUTE = "mute";
        public static final String POWER = "power";
        public static final String GIN = "gin";
        public static final ArrayList ROBOT_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList(MUTE, POWER));
        public static final ArrayList ROBOT_NO_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList(GIN));
    """})
    scanner = ProtocolScanner(src)
    scanner._app_sources = list((src / "sources").rglob("*.java"))
    scanner._collect_str_constants()
    scanner._collect_cmd_lists()
    assert "mute" in scanner._response_cmds
    assert "power" in scanner._response_cmds
    assert "gin" in scanner._no_response_cmds


# ── constant-based command extraction ────────────────────────────────────────

def test_constant_based_commands_resolved(tmp_path):
    src = _make_sources(tmp_path, {"Api.java": """
        public static final String MUTE = "mute";
        public static final String POWER = "power";
        public static final ArrayList ROBOT_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList(MUTE, POWER));
        public static final ArrayList ROBOT_NO_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());

        public void enableMute(boolean enable) {
            jSONObject.put("cmd", MUTE);
            jSONObject.put("enable", enable);
        }
        public void powerOff() {
            jSONObject.put("cmd", POWER);
            jSONObject.put("enable", false);
        }
    """})
    scanner = ProtocolScanner(src)
    transport, discovery, auth, state, commands, events = scanner.scan("com.test")

    cmd_names = {c.cmd for c in commands}
    assert "mute" in cmd_names
    assert "power" in cmd_names


def test_constant_commands_awaits_response(tmp_path):
    src = _make_sources(tmp_path, {"Api.java": """
        public static final String MUTE = "mute";
        public static final ArrayList ROBOT_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList(MUTE));
        public static final ArrayList ROBOT_NO_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());

        void x() { jSONObject.put("cmd", MUTE); jSONObject.put("enable", true); }
    """})
    scanner = ProtocolScanner(src)
    _, _, _, _, commands, _ = scanner.scan("com.test")
    mute = next(c for c in commands if c.cmd == "mute")
    assert mute.awaits_response is True


def test_literal_commands_not_in_response_list(tmp_path):
    src = _make_sources(tmp_path, {"Api.java": """
        public static final ArrayList ROBOT_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());
        public static final ArrayList ROBOT_NO_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());

        void x() { jSONObject.put("cmd", "mode"); jSONObject.put("mode", 3); }
    """})
    scanner = ProtocolScanner(src)
    _, _, _, _, commands, _ = scanner.scan("com.test")
    mode = next((c for c in commands if c.cmd == "mode"), None)
    assert mode is not None
    assert mode.awaits_response is False


# ── events (no-response list → FROM_DEVICE) ───────────────────────────────────

def test_no_response_cmds_become_events(tmp_path):
    src = _make_sources(tmp_path, {"Api.java": """
        public static final String GIN = "gin";
        public static final String STREAMING = "streaming";
        public static final String USER_CONTROL = "user_control";
        public static final ArrayList ROBOT_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());
        public static final ArrayList ROBOT_NO_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList(GIN, STREAMING, USER_CONTROL));
    """})
    scanner = ProtocolScanner(src)
    _, _, _, _, commands, events = scanner.scan("com.test")

    event_cmds = {e.cmd for e in events}
    assert "gin" in event_cmds
    assert "streaming" in event_cmds
    # user_control is excluded from events
    assert "user_control" not in event_cmds
    assert all(e.direction == Direction.FROM_DEVICE for e in events)


# ── mode→action extraction ────────────────────────────────────────────────────

def test_mode_actions_extracted(tmp_path):
    src = _make_sources(tmp_path, {"Adapter.java": """
        public static final ArrayList ROBOT_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());
        public static final ArrayList ROBOT_NO_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());

        void buildCmd() {
            jSONObject.put("cmd", "mode");
            if (str.equals(ctx.getString(R.string.action_turn_left))) {
                jSONObject.put("mode", 3);
            } else if (str.equals(ctx.getString(R.string.action_turn_right))) {
                jSONObject.put("mode", 4);
            }
        }
    """})
    scanner = ProtocolScanner(src)
    scanner.scan("com.test")
    assert scanner.extra.get("mode_actions") == {3: "turn_left", 4: "turn_right"}


# ── field extraction ──────────────────────────────────────────────────────────

def test_fields_extracted_for_literal_cmd(tmp_path):
    src = _make_sources(tmp_path, {"Api.java": """
        public static final ArrayList ROBOT_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());
        public static final ArrayList ROBOT_NO_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());

        void connect() {
            jSONObject.put("cmd", "connectWifi");
            jSONObject.put("ssid", ssid);
            jSONObject.put("wifi_pw", pw);
        }
    """})
    scanner = ProtocolScanner(src)
    _, _, _, _, commands, _ = scanner.scan("com.test")
    connect = next(c for c in commands if c.cmd == "connectWifi")
    field_names = {f.name for f in connect.request_fields}
    assert "ssid" in field_names
    assert "wifi_pw" in field_names


# ── transport detection ───────────────────────────────────────────────────────

def test_websocket_port_detected(tmp_path):
    src = _make_sources(tmp_path, {"WsClient.java": """
        public static final ArrayList ROBOT_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());
        public static final ArrayList ROBOT_NO_RESPONSE_COMMAND_LIST =
            new ArrayList(Arrays.asList());
        new WebSocketClient(new URI("ws://192.168.1.1:8887"));
    """})
    scanner = ProtocolScanner(src)
    transport, _, _, _, _, _ = scanner.scan("com.test")
    assert transport.type == TransportType.WEBSOCKET
    assert transport.port == 8887


# ── snapshot round-trip ───────────────────────────────────────────────────────

def test_bullb_r2d2_snapshot():
    """Integration smoke test: the committed snapshot has the expected shape."""
    from engine.snapshot.harness import load
    ir = load("bullb_r2d2")
    assert ir.transport.port == 8887
    assert ir.discovery.port == 8090
    assert ir.auth.handshake_cmd == "grantAccess"
    assert len(ir.commands) >= 20
    assert len(ir.events) == 3
    assert len(ir.state.fields) == 17
    assert "mode_actions" in ir.extra
    event_cmds = {e.cmd for e in ir.events}
    assert {"gin", "streaming", "updBroadcast"} == event_cmds
