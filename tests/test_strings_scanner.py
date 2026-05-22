# SPDX-License-Identifier: MIT
"""Tests for P5-6 strings.xml scanner and entity-section translation emission."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.emitters import context as ctx_mod
from engine.emitters import hacs_emitter
from engine.extraction.strings_scanner import scan
from engine.ir.models import (
    AuthScheme,
    AuthType,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    EntityHint,
    FieldDef,
    FieldKind,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)


# ── strings_scanner unit tests ────────────────────────────────────────────────

def _write_strings_xml(tmp_path: Path, strings: dict[str, str]) -> Path:
    res_dir = tmp_path / "resources" / "res" / "values"
    res_dir.mkdir(parents=True)
    xml_path = res_dir / "strings.xml"
    items = "\n".join(
        f'    <string name="{k}">{v}</string>' for k, v in strings.items()
    )
    xml_path.write_text(
        f'<?xml version="1.0" encoding="utf-8"?>\n<resources>\n{items}\n</resources>\n'
    )
    return tmp_path


def test_scan_returns_empty_when_no_file(tmp_path):
    assert scan(tmp_path) == {}


def test_scan_returns_error_strings(tmp_path):
    _write_strings_xml(tmp_path, {"error_connect": "Cannot connect to device"})
    result = scan(tmp_path)
    assert "error_connect" in result
    assert result["error_connect"] == "Cannot connect to device"


def test_scan_returns_status_strings(tmp_path):
    _write_strings_xml(tmp_path, {"status_offline": "Device is offline"})
    result = scan(tmp_path)
    assert "status_offline" in result


def test_scan_returns_fail_strings(tmp_path):
    _write_strings_xml(tmp_path, {"connection_failed": "Connection failed"})
    result = scan(tmp_path)
    assert "connection_failed" in result


def test_scan_excludes_menu_strings(tmp_path):
    _write_strings_xml(tmp_path, {"menu_settings": "Settings"})
    assert "menu_settings" not in scan(tmp_path)


def test_scan_excludes_activity_strings(tmp_path):
    _write_strings_xml(tmp_path, {"activity_main": "Main"})
    assert "activity_main" not in scan(tmp_path)


def test_scan_excludes_app_name(tmp_path):
    _write_strings_xml(tmp_path, {"app_name": "My Device"})
    assert "app_name" not in scan(tmp_path)


def test_scan_excludes_short_values(tmp_path):
    _write_strings_xml(tmp_path, {"error_x": "N/A"})
    assert "error_x" not in scan(tmp_path)


def test_scan_excludes_long_values(tmp_path):
    _write_strings_xml(tmp_path, {"error_long": "x" * 201})
    assert "error_long" not in scan(tmp_path)


def test_scan_excludes_format_specifiers(tmp_path):
    _write_strings_xml(tmp_path, {"error_fmt": "Error code %d"})
    assert "error_fmt" not in scan(tmp_path)


def test_scan_excludes_html_tags(tmp_path):
    _write_strings_xml(tmp_path, {"error_html": "Check <b>connection</b>"})
    assert "error_html" not in scan(tmp_path)


def test_scan_excludes_irrelevant_strings(tmp_path):
    _write_strings_xml(tmp_path, {"button_ok": "OK", "hint_name": "Enter name"})
    result = scan(tmp_path)
    assert "button_ok" not in result
    assert "hint_name" not in result


def test_scan_returns_disconnect_strings(tmp_path):
    _write_strings_xml(tmp_path, {"msg_disconnected": "Device disconnected"})
    assert "msg_disconnected" in scan(tmp_path)


def test_scan_handles_malformed_xml(tmp_path):
    res_dir = tmp_path / "resources" / "res" / "values"
    res_dir.mkdir(parents=True)
    (res_dir / "strings.xml").write_text("<resources><string name=")
    assert scan(tmp_path) == {}


# ── context builder tests ─────────────────────────────────────────────────────

def _make_ir(**overrides) -> ProtocolIR:
    defaults = dict(
        apk_path="/tmp/test.apk",
        package_name="com.example.device",
        app_name="My Device",
        version_name="1.0.0",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        # WS sensors come from state.fields; switches come from commands
        state=StateSchema(fields=[
            FieldDef(name="temperature", kind=FieldKind.NUMBER, entity_hint=EntityHint.SENSOR),
        ]),
        commands=[
            Endpoint(cmd="power", transport=TransportType.WEBSOCKET,
                     direction=Direction.TO_DEVICE, entity_hint=EntityHint.SWITCH),
        ],
        events=[],
        extra={},
    )
    defaults.update(overrides)
    return ProtocolIR(**defaults)


def test_context_has_device_errors_from_android_strings():
    ir = _make_ir(extra={"android_strings": {"error_connect": "Cannot connect to device"}})
    ctx = ctx_mod.build(ir)
    assert any(e["key"] == "error_connect" and "connect" in e["msg"].lower()
               for e in ctx["device_errors"])


def test_context_device_errors_key_is_snake_case():
    ir = _make_ir(extra={"android_strings": {"errorConnectFailed": "Connect failed"}})
    ctx = ctx_mod.build(ir)
    assert any(e["key"] == "error_connect_failed" for e in ctx["device_errors"])


def test_context_no_device_errors_when_no_android_strings():
    ir = _make_ir(extra={})
    ctx = ctx_mod.build(ir)
    assert ctx["device_errors"] == []


def test_context_status_string_not_in_device_errors():
    # status strings are user-facing but not "errors" → excluded from device_errors
    ir = _make_ir(extra={"android_strings": {"status_online": "Device is online"}})
    ctx = ctx_mod.build(ir)
    assert not any(e["key"] == "status_online" for e in ctx["device_errors"])


def test_context_entity_sections_has_sensor():
    ir = _make_ir()
    ctx = ctx_mod.build(ir)
    assert "sensor" in ctx["entity_sections"]


def test_context_entity_sections_sensor_has_key():
    ir = _make_ir()
    ctx = ctx_mod.build(ir)
    assert "temperature" in ctx["entity_sections"]["sensor"]


def test_context_entity_sections_has_switch():
    ir = _make_ir()
    ctx = ctx_mod.build(ir)
    assert "switch" in ctx["entity_sections"]


def test_context_entity_sections_switch_has_key():
    ir = _make_ir()
    ctx = ctx_mod.build(ir)
    assert "power" in ctx["entity_sections"]["switch"]


def test_context_entity_sections_name_matches():
    ir = _make_ir()
    ctx = ctx_mod.build(ir)
    assert ctx["entity_sections"]["sensor"]["temperature"]["name"] == "Temperature"


def test_context_entity_sections_empty_when_no_entities():
    ir = _make_ir(commands=[], events=[], state=StateSchema(fields=[]))
    ctx = ctx_mod.build(ir)
    assert ctx["entity_sections"] == {}


# ── emission tests ────────────────────────────────────────────────────────────

def _emit(tmp_path: Path, ir: ProtocolIR) -> Path:
    ctx = ctx_mod.build(ir)
    return hacs_emitter.emit(ctx, tmp_path)


def test_strings_json_is_valid_json(tmp_path):
    domain_dir = _emit(tmp_path, _make_ir())
    text = (domain_dir / "strings.json").read_text()
    parsed = json.loads(text)
    assert "config" in parsed


def test_en_json_is_valid_json(tmp_path):
    domain_dir = _emit(tmp_path, _make_ir())
    text = (domain_dir / "translations" / "en.json").read_text()
    parsed = json.loads(text)
    assert "config" in parsed


def test_en_json_has_entity_section(tmp_path):
    domain_dir = _emit(tmp_path, _make_ir())
    text = (domain_dir / "translations" / "en.json").read_text()
    parsed = json.loads(text)
    assert "entity" in parsed


def test_en_json_entity_sensor_has_temperature(tmp_path):
    domain_dir = _emit(tmp_path, _make_ir())
    parsed = json.loads((domain_dir / "translations" / "en.json").read_text())
    assert parsed["entity"]["sensor"]["temperature"]["name"] == "Temperature"


def test_en_json_entity_switch_has_power(tmp_path):
    domain_dir = _emit(tmp_path, _make_ir())
    parsed = json.loads((domain_dir / "translations" / "en.json").read_text())
    assert parsed["entity"]["switch"]["power"]["name"] == "Power"


def test_strings_json_has_entity_section(tmp_path):
    domain_dir = _emit(tmp_path, _make_ir())
    parsed = json.loads((domain_dir / "strings.json").read_text())
    assert "entity" in parsed


def test_en_json_has_device_error_key(tmp_path):
    ir = _make_ir(extra={"android_strings": {"error_auth_fail": "Authentication failed"}})
    domain_dir = _emit(tmp_path, ir)
    parsed = json.loads((domain_dir / "translations" / "en.json").read_text())
    assert "error_auth_fail" in parsed["config"]["error"]


def test_en_json_device_error_value_is_original_string(tmp_path):
    ir = _make_ir(extra={"android_strings": {"error_auth_fail": "Authentication failed"}})
    domain_dir = _emit(tmp_path, ir)
    parsed = json.loads((domain_dir / "translations" / "en.json").read_text())
    assert parsed["config"]["error"]["error_auth_fail"] == "Authentication failed"


def test_en_json_no_entity_section_when_no_entities(tmp_path):
    ir = _make_ir(commands=[], events=[], state=StateSchema(fields=[]))
    domain_dir = _emit(tmp_path, ir)
    parsed = json.loads((domain_dir / "translations" / "en.json").read_text())
    assert "entity" not in parsed
