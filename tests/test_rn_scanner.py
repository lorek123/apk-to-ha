# SPDX-License-Identifier: MIT
"""Tests for P1-6 React Native scanner."""
from __future__ import annotations

from pathlib import Path

import pytest

from engine.extraction.rn_scanner import (
    RNScanner,
    _ast_extract,
    _hermes_extract_strings,
    _path_to_cmd,
    _port_from_url,
    _read_bundle,
)
from engine.ir.models import AuthType, Direction, DiscoveryType, TransportType


def _write(tmp_path: Path, content: str, name: str = "index.android.bundle") -> Path:
    p = tmp_path / "resources" / "assets" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


# ── helpers ───────────────────────────────────────────────────────────────────

def test_port_from_url_ws() -> None:
    assert _port_from_url("ws://192.168.1.1:8887/ws") == 8887


def test_port_from_url_http() -> None:
    assert _port_from_url("http://device.local:9000/api") == 9000


def test_port_from_url_none() -> None:
    assert _port_from_url("ws://host/path") is None


def test_path_to_cmd_simple() -> None:
    assert _path_to_cmd("http://x.com/api/v1/powerControl") == "powerControl"


def test_path_to_cmd_hyphenated() -> None:
    assert _path_to_cmd("/api/v1/set-brightness") == "setBrightness"


def test_path_to_cmd_skips_digit() -> None:
    assert _path_to_cmd("/api/v1/devices/123") is None


def test_path_to_cmd_dict_input() -> None:
    assert _path_to_cmd({"url": "http://x.com/api/v1/status", "method": "GET"}) == "status"


# ── _hermes_extract_strings ───────────────────────────────────────────────────

def test_hermes_extract_strings_finds_urls() -> None:
    # Simulate Hermes bytecode with embedded strings
    payload = b"\xc6\x1f\xbc\x03" + b"\x00" * 20
    payload += b"http://192.168.1.1:8080/api/v1/status\x00"
    payload += b"\x01\x02\x03"
    payload += b"grantAccess\x00"
    result = _hermes_extract_strings(payload)
    assert "http://192.168.1.1:8080/api/v1/status" in result
    assert "grantAccess" in result


# ── _ast_extract ──────────────────────────────────────────────────────────────

def test_ast_extract_fetch_call() -> None:
    import esprima
    src = "fetch('/api/v1/power', {method: 'POST'});"
    tree = esprima.parseScript(src, tolerant=True)
    data = _ast_extract(tree)
    assert "/api/v1/power" in data["fetch_calls"]


def test_ast_extract_axios_get() -> None:
    import esprima
    src = "axios.get('/api/v1/status');"
    tree = esprima.parseScript(src, tolerant=True)
    data = _ast_extract(tree)
    assert "/api/v1/status" in data["fetch_calls"]


def test_ast_extract_websocket_ctor() -> None:
    import esprima
    src = "var ws = new WebSocket('ws://192.168.1.1:8887');"
    tree = esprima.parseScript(src, tolerant=True)
    data = _ast_extract(tree)
    assert "ws://192.168.1.1:8887" in data["ws_ctors"]


def test_ast_extract_cmd_literal() -> None:
    import esprima
    src = "ws.send(JSON.stringify({cmd: 'powerControl', enable: true}));"
    tree = esprima.parseScript(src, tolerant=True)
    data = _ast_extract(tree)
    assert "powerControl" in data["cmd_literals"]


def test_ast_extract_cmd_fields() -> None:
    import esprima
    src = "send({cmd: 'setMode', mode: 1, speed: 2.5});"
    tree = esprima.parseScript(src, tolerant=True)
    data = _ast_extract(tree)
    assert "setMode" in data["cmd_literals"]


# ── RNScanner integration ─────────────────────────────────────────────────────

_BUNDLE_WS = """\
var BASE = 'ws://192.168.1.1:8887';
var ws = new WebSocket(BASE);
ws.onopen = function() {
    ws.send(JSON.stringify({cmd: 'grantAccess', uuid: '123', device_name: 'HA'}));
};
ws.onmessage = function(e) {
    var d = JSON.parse(e.data);
    if (d.cmd === 'gin') { updateState(d); }
};
function powerOn() {
    ws.send(JSON.stringify({cmd: 'powerControl', enable: true}));
}
function setMode(m) {
    ws.send(JSON.stringify({cmd: 'setMode', mode: m}));
}
"""

_BUNDLE_HTTP = """\
var BASE_URL = 'http://192.168.1.1:8080';
function getStatus() {
    return fetch(BASE_URL + '/api/v1/status', {method: 'GET'});
}
function setLight(enable) {
    return fetch(BASE_URL + '/api/v1/light', {
        method: 'POST',
        body: JSON.stringify({enable: enable})
    });
}
function authenticate(token) {
    return axios.post('/api/v1/auth/login', {token: token});
}
"""


def test_rn_scanner_ws_transport(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_WS)
    t, *_ = RNScanner(tmp_path).scan("com.example")
    assert t.type == TransportType.WEBSOCKET
    assert t.port == 8887


def test_rn_scanner_ws_commands(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_WS)
    _, _, _, _, commands, _ = RNScanner(tmp_path).scan("com.example")
    cmd_names = {ep.cmd for ep in commands}
    assert "powerControl" in cmd_names
    assert "setMode" in cmd_names


def test_rn_scanner_ws_auth_detected(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_WS)
    _, _, auth, _, _, _ = RNScanner(tmp_path).scan("com.example")
    assert auth.type == AuthType.HANDSHAKE
    assert auth.handshake_cmd == "grantAccess"


def test_rn_scanner_ws_auth_not_in_commands(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_WS)
    _, _, _, _, commands, _ = RNScanner(tmp_path).scan("com.example")
    assert not any(ep.cmd == "grantAccess" for ep in commands)


def test_rn_scanner_http_transport(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_HTTP)
    t, *_ = RNScanner(tmp_path).scan("com.example")
    assert t.type in (TransportType.HTTP_REST, TransportType.WEBSOCKET)


def test_rn_scanner_http_commands(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_HTTP)
    _, _, _, _, commands, _ = RNScanner(tmp_path).scan("com.example")
    cmd_names = {ep.cmd for ep in commands}
    # /api/v1/status → status, /api/v1/light → light
    assert any(c in cmd_names for c in ("status", "light", "login"))


def test_rn_scanner_no_bundle_returns_defaults(tmp_path: Path) -> None:
    t, disc, auth, state, cmds, evts = RNScanner(tmp_path).scan("com.example")
    assert t.type == TransportType.HTTP_REST
    assert cmds == []


def test_rn_scanner_discovery_is_none(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_WS)
    _, discovery, _, _, _, _ = RNScanner(tmp_path).scan("com.example")
    assert discovery.type == DiscoveryType.NONE


def test_rn_scanner_command_confidence_below_native(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_WS)
    _, _, _, _, commands, _ = RNScanner(tmp_path).scan("com.example")
    # All RN commands should have confidence < 1.0 (Bronze tier)
    assert all(ep.confidence < 1.0 for ep in commands)


def test_rn_scanner_hermes_bundle(tmp_path: Path) -> None:
    # Hermes magic + embedded strings
    import struct
    payload = b"\xc6\x1f\xbc\x03" + b"\x00" * 100
    payload += b"ws://192.168.1.1:8887\x00"
    payload += b"powerControl\x00"
    p = tmp_path / "resources" / "assets" / "index.android.bundle"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(payload)
    # Should not crash, should extract ws transport from string
    t, _, _, _, _, _ = RNScanner(tmp_path).scan("com.example")
    assert t.type == TransportType.WEBSOCKET


def test_rn_scanner_framework_detected_by_classifier(tmp_path: Path) -> None:
    _write(tmp_path, _BUNDLE_WS)
    from engine.ingestion.classifier import classify
    assert classify(tmp_path).value == "react_native"
