# SPDX-License-Identifier: MIT
"""Tests for P4-6 Bleak BLE client template rendering."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from engine.emitters import context as ctx_mod
from engine.emitters import sdk_emitter
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


def _make_ble_ir(**overrides: Any) -> ProtocolIR:
    """IR with two BLE characteristics: one write, one notify."""
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
            Endpoint(
                cmd="write",
                transport=TransportType.BLE,
                direction=Direction.TO_DEVICE,
                entity_hint=EntityHint.SWITCH,
                confidence=0.7,
            ),
        ],
        events=[
            Endpoint(
                cmd="notify",
                transport=TransportType.BLE,
                direction=Direction.FROM_DEVICE,
                entity_hint=EntityHint.SENSOR,
                confidence=0.7,
            ),
        ],
        extra={
            "ble_service_uuids": ["0000fff0-0000-1000-8000-00805f9b34fb"],
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


def _build_ctx(ir: ProtocolIR) -> dict[str, Any]:
    return ctx_mod.build(ir)


# ── context builder ───────────────────────────────────────────────────────────

def test_has_ble_true_for_ble_ir() -> None:
    ctx = _build_ctx(_make_ble_ir())
    assert ctx["has_ble"] is True


def test_has_ble_false_for_http_ir() -> None:
    ir = _make_ble_ir(
        transport=TransportContract(type=TransportType.HTTP_REST, port=8080),
        commands=[
            Endpoint(
                cmd="powerControl",
                transport=TransportType.HTTP_REST,
                direction=Direction.TO_DEVICE,
            )
        ],
        events=[],
        extra={},
    )
    ctx = _build_ctx(ir)
    assert ctx["has_ble"] is False


def test_ble_chars_populated() -> None:
    ctx = _build_ctx(_make_ble_ir())
    keys = {c["cmd"] for c in ctx["ble_chars"]}
    assert "write" in keys
    assert "notify" in keys


def test_ble_char_has_uuid() -> None:
    ctx = _build_ctx(_make_ble_ir())
    write_char = next(c for c in ctx["ble_chars"] if c["cmd"] == "write")
    assert write_char["uuid"] == "0000fff1-0000-1000-8000-00805f9b34fb"


def test_ble_char_has_access() -> None:
    ctx = _build_ctx(_make_ble_ir())
    write_char = next(c for c in ctx["ble_chars"] if c["cmd"] == "write")
    assert "write" in write_char["access"]


def test_ble_char_key_is_snake_case() -> None:
    ir = _make_ble_ir(
        commands=[
            Endpoint(cmd="batteryLevel", transport=TransportType.BLE,
                     direction=Direction.TO_DEVICE, confidence=0.7),
        ],
        events=[],
        extra={
            "ble_char_uuids": {"batteryLevel": "0000180f-0000-1000-8000-00805f9b34fb"},
            "ble_char_access": {"batteryLevel": ["read"]},
        },
    )
    ctx = _build_ctx(ir)
    char = next(c for c in ctx["ble_chars"] if c["cmd"] == "batteryLevel")
    assert char["key"] == "battery_level"


def test_ble_service_uuids_in_ctx() -> None:
    ctx = _build_ctx(_make_ble_ir())
    assert "0000fff0-0000-1000-8000-00805f9b34fb" in ctx["ble_service_uuids"]


def test_ble_chars_deduped() -> None:
    # Same UUID in commands and events — should appear once
    uuid = "0000fff1-0000-1000-8000-00805f9b34fb"
    ir = _make_ble_ir(
        commands=[Endpoint(cmd="rwChar", transport=TransportType.BLE,
                           direction=Direction.TO_DEVICE, confidence=0.7)],
        events=[Endpoint(cmd="rwChar", transport=TransportType.BLE,
                          direction=Direction.FROM_DEVICE, confidence=0.7)],
        extra={
            "ble_char_uuids": {"rwChar": uuid},
            "ble_char_access": {"rwChar": ["read", "write"]},
        },
    )
    ctx = _build_ctx(ir)
    assert sum(1 for c in ctx["ble_chars"] if c["uuid"] == uuid) == 1


# ── template rendering ────────────────────────────────────────────────────────

def test_ble_client_file_emitted(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    pkg_dir = tmp_path / ctx["sdk_package"]
    assert (pkg_dir / "ble_client.py").exists()


def test_ble_test_file_emitted(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    assert (tmp_path / "tests" / "test_ble_client.py").exists()


def test_ble_client_not_emitted_for_http(tmp_path: Path) -> None:
    ir = _make_ble_ir(
        transport=TransportContract(type=TransportType.HTTP_REST, port=8080),
        commands=[
            Endpoint(cmd="powerControl", transport=TransportType.HTTP_REST,
                     direction=Direction.TO_DEVICE),
        ],
        events=[],
        extra={},
    )
    ctx = _build_ctx(ir)
    sdk_emitter.emit(ctx, tmp_path)
    pkg_dir = tmp_path / ctx["sdk_package"]
    assert not (pkg_dir / "ble_client.py").exists()


def test_ble_client_contains_write_method(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    pkg_dir = tmp_path / ctx["sdk_package"]
    content = (pkg_dir / "ble_client.py").read_text()
    assert "async def write_write" in content
    assert "0000fff1-0000-1000-8000-00805f9b34fb" in content


def test_ble_client_contains_notify_methods(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    pkg_dir = tmp_path / ctx["sdk_package"]
    content = (pkg_dir / "ble_client.py").read_text()
    assert "start_notify_notify" in content
    assert "stop_notify_notify" in content
    assert "on_notify_update" in content


def test_ble_client_has_spdx_header(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    pkg_dir = tmp_path / ctx["sdk_package"]
    first_line = (pkg_dir / "ble_client.py").read_text().splitlines()[0]
    assert "SPDX-License-Identifier: MIT" in first_line


def test_ble_client_has_reconnect_logic(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    pkg_dir = tmp_path / ctx["sdk_package"]
    content = (pkg_dir / "ble_client.py").read_text()
    assert "ensure_connected" in content
    assert "_MAX_RECONNECT_ATTEMPTS" in content


def test_ble_client_is_async_context_manager(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    pkg_dir = tmp_path / ctx["sdk_package"]
    content = (pkg_dir / "ble_client.py").read_text()
    assert "__aenter__" in content
    assert "__aexit__" in content


def test_ble_test_contains_retry_test(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    content = (tmp_path / "tests" / "test_ble_client.py").read_text()
    assert "test_connect_retries_on_failure" in content


def test_ble_test_has_spdx_header(tmp_path: Path) -> None:
    ctx = _build_ctx(_make_ble_ir())
    sdk_emitter.emit(ctx, tmp_path)
    first_line = (tmp_path / "tests" / "test_ble_client.py").read_text().splitlines()[0]
    assert "SPDX-License-Identifier: MIT" in first_line
