# SPDX-License-Identifier: MIT
"""Tests for P5-8 multi-protocol entity mapping (BLE characteristics → HA platforms)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from engine.emitters import context as ctx_mod
from engine.emitters import hacs_emitter
from engine.extraction.entity_classifier import _hint_endpoint, classify
from engine.ir.models import (
    AuthScheme,
    AuthType,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    EntityHint,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)

# ── helpers ───────────────────────────────────────────────────────────────────


def _ble_ep(cmd: str, direction: Direction, hint: EntityHint | None = None) -> Endpoint:
    return Endpoint(
        cmd=cmd,
        transport=TransportType.BLE,
        direction=direction,
        entity_hint=hint,
        confidence=0.7,
    )


def _make_ble_ir(**overrides: Any) -> ProtocolIR:
    defaults = dict(
        apk_path="/tmp/test.apk",
        package_name="com.example.bledevice",
        app_name="BLE Device",
        version_name="1.0.0",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.BLE),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(),
        commands=[
            _ble_ep("write", Direction.TO_DEVICE, EntityHint.SWITCH),
        ],
        events=[
            _ble_ep("notify", Direction.FROM_DEVICE, EntityHint.SENSOR),
        ],
        extra={
            "ble_char_uuids": {
                "write": "0000fff1-0000-1000-8000-00805f9b34fb",
                "notify": "0000fff2-0000-1000-8000-00805f9b34fb",
            },
            "ble_char_access": {
                "write": ["write"],
                "notify": ["notify"],
            },
        },
    )
    defaults.update(overrides)
    return ProtocolIR(**defaults)


# ── entity_classifier ─────────────────────────────────────────────────────────


def test_classifier_preserves_ble_scanner_hint() -> None:
    ep = _ble_ep("write", Direction.TO_DEVICE, EntityHint.SWITCH)
    result = _hint_endpoint(ep, set())
    assert result.entity_hint == EntityHint.SWITCH


def test_classifier_ble_notify_without_hint_gets_sensor() -> None:
    ep = _ble_ep("notify", Direction.FROM_DEVICE, hint=None)
    result = _hint_endpoint(ep, set())
    assert result.entity_hint == EntityHint.SENSOR


def test_classifier_ble_write_without_hint_gets_switch() -> None:
    ep = _ble_ep("cmd", Direction.TO_DEVICE, hint=None)
    result = _hint_endpoint(ep, set())
    assert result.entity_hint == EntityHint.SWITCH


def test_classify_full_ir_sets_hints() -> None:
    ir = _make_ble_ir(
        commands=[_ble_ep("write", Direction.TO_DEVICE, hint=None)],
        events=[_ble_ep("notify", Direction.FROM_DEVICE, hint=None)],
    )
    classified = classify(ir)
    assert classified.commands[0].entity_hint == EntityHint.SWITCH
    assert classified.events[0].entity_hint == EntityHint.SENSOR


# ── context builder ───────────────────────────────────────────────────────────


def test_ble_sensors_in_context() -> None:
    ctx = ctx_mod.build(_make_ble_ir())
    assert any(s["cmd"] == "notify" for s in ctx["ble_sensors"])


def test_ble_switches_in_context() -> None:
    ctx = ctx_mod.build(_make_ble_ir())
    assert any(s["cmd"] == "write" for s in ctx["ble_switches"])


def test_ble_sensor_has_uuid() -> None:
    ctx = ctx_mod.build(_make_ble_ir())
    sensor = next(s for s in ctx["ble_sensors"] if s["cmd"] == "notify")
    assert sensor["uuid"] == "0000fff2-0000-1000-8000-00805f9b34fb"


def test_ble_switch_has_uuid() -> None:
    ctx = ctx_mod.build(_make_ble_ir())
    switch = next(s for s in ctx["ble_switches"] if s["cmd"] == "write")
    assert switch["uuid"] == "0000fff1-0000-1000-8000-00805f9b34fb"


def test_ble_sensor_key_is_snake_case() -> None:
    ir = _make_ble_ir(
        events=[_ble_ep("batteryLevel", Direction.FROM_DEVICE, EntityHint.SENSOR)],
        extra={
            "ble_char_uuids": {
                "write": "0000fff1-0000-1000-8000-00805f9b34fb",
                "batteryLevel": "0000180f-0000-1000-8000-00805f9b34fb",
            },
            "ble_char_access": {
                "write": ["write"],
                "batteryLevel": ["notify"],
            },
        },
    )
    ctx = ctx_mod.build(ir)
    sensor = next(s for s in ctx["ble_sensors"] if s["cmd"] == "batteryLevel")
    assert sensor["key"] == "battery_level"


def test_sensor_platform_added_when_ble_sensors() -> None:
    ctx = ctx_mod.build(_make_ble_ir())
    assert "sensor" in ctx["platforms"]


def test_switch_platform_added_when_ble_switches() -> None:
    ctx = ctx_mod.build(_make_ble_ir())
    assert "switch" in ctx["platforms"]


# ── HACS emission ─────────────────────────────────────────────────────────────


def _emit_hacs(tmp_path: Path, ir: ProtocolIR | None = None) -> Path:
    ctx = ctx_mod.build(ir or _make_ble_ir())
    return hacs_emitter.emit(ctx, tmp_path)


def test_ble_coordinator_emitted(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    assert (domain_dir / "ble_coordinator.py").exists()


def test_ble_coordinator_not_emitted_for_http(tmp_path: Path) -> None:
    ir = _make_ble_ir(
        transport=TransportContract(type=TransportType.HTTP_REST, port=8080),
        commands=[
            Endpoint(cmd="power", transport=TransportType.HTTP_REST, direction=Direction.TO_DEVICE)
        ],
        events=[],
        extra={},
    )
    ctx = ctx_mod.build(ir)
    domain_dir = hacs_emitter.emit(ctx, tmp_path)
    assert not (domain_dir / "ble_coordinator.py").exists()


def test_sensor_py_has_ble_sensor_class(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "sensor.py").read_text()
    assert "BleSensor" in content


def test_switch_py_has_ble_switch_class(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "switch.py").read_text()
    assert "BleSwitch" in content


def test_sensor_py_uses_ble_coordinator(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "sensor.py").read_text()
    assert "ble_coordinator" in content


def test_switch_py_uses_write_char(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "switch.py").read_text()
    assert "write_char" in content


def test_init_imports_ble_client(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "__init__.py").read_text()
    assert "BleClient" in content


def test_init_imports_ble_coordinator(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "__init__.py").read_text()
    assert "BleCoordinator" in content


def test_init_disconnects_ble_on_unload(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "__init__.py").read_text()
    assert "ble_client.disconnect" in content


def test_entity_base_has_ble_entity_class(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "entity_base.py").read_text()
    assert "BleEntity" in content


def test_ble_coordinator_has_spdx_header(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    first_line = (domain_dir / "ble_coordinator.py").read_text().splitlines()[0]
    assert "SPDX-License-Identifier: MIT" in first_line


def test_ble_coordinator_has_notify_handler(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "ble_coordinator.py").read_text()
    assert "_handle_notify" in content
    assert "start_notify_notify" in content


def test_ble_coordinator_uses_data_update_coordinator(tmp_path: Path) -> None:
    domain_dir = _emit_hacs(tmp_path)
    content = (domain_dir / "ble_coordinator.py").read_text()
    assert "DataUpdateCoordinator" in content
    assert "_POLL_INTERVAL" in content
