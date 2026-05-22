# SPDX-License-Identifier: MIT
"""Tests for P2-8 BLE/GATT endpoint scanner."""
from __future__ import annotations

from pathlib import Path

import pytest

from engine.extraction.ble_scanner import (
    BLEScanner,
    _char_to_endpoint,
    _CharInfo,
    _scan_file,
    _uuid_to_cmd,
)
from engine.ir.models import Direction, EntityHint, TransportType


# ── Java fixture text ──────────────────────────────────────────────────────────

_JAVA_BLE = """\
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import java.util.UUID;

public class BleManager {
    private static final UUID SERVICE_UUID =
        UUID.fromString("0000fff0-0000-1000-8000-00805f9b34fb");
    private static final UUID CHAR_WRITE_UUID =
        UUID.fromString("0000fff1-0000-1000-8000-00805f9b34fb");
    private static final UUID CHAR_NOTIFY_UUID =
        UUID.fromString("0000fff2-0000-1000-8000-00805f9b34fb");
    private static final UUID CHAR_READ_UUID =
        UUID.fromString("0000fff3-0000-1000-8000-00805f9b34fb");

    public void setup(BluetoothGatt gatt) {
        BluetoothGattService svc = gatt.getService(SERVICE_UUID);

        BluetoothGattCharacteristic cmdChar = svc.getCharacteristic(CHAR_WRITE_UUID);
        cmdChar.setValue(data);
        gatt.writeCharacteristic(cmdChar);

        BluetoothGattCharacteristic notifyChar = svc.getCharacteristic(CHAR_NOTIFY_UUID);
        gatt.setCharacteristicNotification(notifyChar, true);

        BluetoothGattCharacteristic readChar = svc.getCharacteristic(CHAR_READ_UUID);
        gatt.readCharacteristic(readChar);
    }
}
"""

_JAVA_NO_BLE = """\
public class NetworkClient {
    public void connect() {
        // HTTP client, no BLE
        okhttp3.OkHttpClient client = new okhttp3.OkHttpClient();
    }
}
"""

_JAVA_BLE_ONLY_WRITE = """\
import android.bluetooth.BluetoothGatt;
import java.util.UUID;

public class BleWriter {
    private static final UUID CMD_UUID =
        UUID.fromString("abcd1234-0000-1000-8000-00805f9b34fb");

    public void send(BluetoothGatt gatt, byte[] data) {
        BluetoothGattCharacteristic ch = gatt.getService(svcUuid).getCharacteristic(CMD_UUID);
        ch.setValue(data);
        gatt.writeCharacteristic(ch);
    }
}
"""

_JAVA_BLE_WRITE_NOTIFY = """\
import android.bluetooth.BluetoothGatt;
import java.util.UUID;

public class BleDevice {
    private static final UUID SERVICE_UUID =
        UUID.fromString("12345678-1234-1234-1234-123456789abc");
    private static final UUID WRITE_UUID =
        UUID.fromString("12345678-1234-1234-1234-000000000001");
    private static final UUID NOTIFY_UUID =
        UUID.fromString("12345678-1234-1234-1234-000000000002");

    public void init(BluetoothGatt gatt) {
        BluetoothGattService svc = gatt.getService(SERVICE_UUID);
        gatt.writeCharacteristic(svc.getCharacteristic(WRITE_UUID));
        gatt.setCharacteristicNotification(svc.getCharacteristic(NOTIFY_UUID), true);
    }
}
"""


# ── _uuid_to_cmd ──────────────────────────────────────────────────────────────

def test_uuid_to_cmd_strips_char_prefix():
    assert _uuid_to_cmd("CHAR_WRITE_UUID", "0000fff1-0000-1000-8000-00805f9b34fb") == "write"


def test_uuid_to_cmd_strips_uuid_suffix():
    assert _uuid_to_cmd("CMD_UUID", "abcd1234-0000-1000-8000-00805f9b34fb") == "cmd"


def test_uuid_to_cmd_camel_case():
    assert _uuid_to_cmd("CHAR_BATTERY_LEVEL_UUID", "...") == "batteryLevel"


def test_uuid_to_cmd_no_const_name():
    cmd = _uuid_to_cmd(None, "abcd1234-5678-9abc-def0-123456789abc")
    assert cmd.startswith("char")
    assert len(cmd) > 4


def test_uuid_to_cmd_characteristic_prefix():
    assert _uuid_to_cmd("CHARACTERISTIC_POWER", "...") == "power"


# ── _char_to_endpoint ─────────────────────────────────────────────────────────

def test_char_to_endpoint_write_is_to_device():
    ch = _CharInfo(const_name="CMD_UUID", uuid="0000fff1-...", access={"write"})
    ep = _char_to_endpoint(ch)
    assert ep.direction == Direction.TO_DEVICE
    assert ep.transport == TransportType.BLE


def test_char_to_endpoint_notify_is_from_device():
    ch = _CharInfo(const_name="NOTIFY_UUID", uuid="0000fff2-...", access={"notify"})
    ep = _char_to_endpoint(ch)
    assert ep.direction == Direction.FROM_DEVICE


def test_char_to_endpoint_read_is_from_device():
    ch = _CharInfo(const_name="READ_UUID", uuid="0000fff3-...", access={"read"})
    ep = _char_to_endpoint(ch)
    assert ep.direction == Direction.FROM_DEVICE


def test_char_to_endpoint_write_hint_is_switch():
    ch = _CharInfo(const_name="CMD_UUID", uuid="0000fff1-...", access={"write"})
    ep = _char_to_endpoint(ch)
    assert ep.entity_hint == EntityHint.SWITCH


def test_char_to_endpoint_notify_hint_is_sensor():
    ch = _CharInfo(const_name="NOTIFY_UUID", uuid="0000fff2-...", access={"notify"})
    ep = _char_to_endpoint(ch)
    assert ep.entity_hint == EntityHint.SENSOR


def test_char_to_endpoint_read_hint_is_sensor():
    ch = _CharInfo(const_name="READ_UUID", uuid="0000fff3-...", access={"read"})
    ep = _char_to_endpoint(ch)
    assert ep.entity_hint == EntityHint.SENSOR


def test_char_to_endpoint_confidence_below_1():
    ch = _CharInfo(const_name="CMD_UUID", uuid="0000fff1-...", access={"write"})
    ep = _char_to_endpoint(ch)
    assert ep.confidence < 1.0


# ── _scan_file ────────────────────────────────────────────────────────────────

def test_scan_file_finds_service_uuid():
    chars, services = _scan_file(_JAVA_BLE, "BleManager")
    assert "0000fff0-0000-1000-8000-00805f9b34fb" in services


def test_scan_file_service_not_in_chars():
    chars, _ = _scan_file(_JAVA_BLE, "BleManager")
    uuids = {c.uuid for c in chars}
    assert "0000fff0-0000-1000-8000-00805f9b34fb" not in uuids


def test_scan_file_finds_write_characteristic():
    chars, _ = _scan_file(_JAVA_BLE, "BleManager")
    uuids = {c.uuid for c in chars}
    assert "0000fff1-0000-1000-8000-00805f9b34fb" in uuids


def test_scan_file_write_access():
    chars, _ = _scan_file(_JAVA_BLE, "BleManager")
    ch = next(c for c in chars if c.uuid == "0000fff1-0000-1000-8000-00805f9b34fb")
    assert "write" in ch.access


def test_scan_file_notify_access():
    chars, _ = _scan_file(_JAVA_BLE, "BleManager")
    ch = next(c for c in chars if c.uuid == "0000fff2-0000-1000-8000-00805f9b34fb")
    assert "notify" in ch.access


def test_scan_file_read_access():
    chars, _ = _scan_file(_JAVA_BLE, "BleManager")
    ch = next(c for c in chars if c.uuid == "0000fff3-0000-1000-8000-00805f9b34fb")
    assert "read" in ch.access


def test_scan_file_no_ble_returns_empty():
    chars, services = _scan_file(_JAVA_NO_BLE, "NetworkClient")
    assert chars == []
    assert services == []


# ── BLEScanner integration ────────────────────────────────────────────────────

def _write_java(tmp_path: Path, content: str, name: str = "BleManager.java") -> Path:
    p = tmp_path / "sources" / "com" / "example" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def test_ble_scanner_transport(tmp_path):
    _write_java(tmp_path, _JAVA_BLE)
    t, *_ = BLEScanner(tmp_path).scan("com.example")
    assert t.type == TransportType.BLE


def test_ble_scanner_commands(tmp_path):
    _write_java(tmp_path, _JAVA_BLE)
    _, _, _, _, commands, _ = BLEScanner(tmp_path).scan("com.example")
    assert any(ep.direction == Direction.TO_DEVICE for ep in commands)


def test_ble_scanner_events(tmp_path):
    _write_java(tmp_path, _JAVA_BLE)
    _, _, _, _, _, events = BLEScanner(tmp_path).scan("com.example")
    assert any(ep.direction == Direction.FROM_DEVICE for ep in events)


def test_ble_scanner_service_uuid_in_extra(tmp_path):
    _write_java(tmp_path, _JAVA_BLE)
    scanner = BLEScanner(tmp_path)
    scanner.scan("com.example")
    assert "0000fff0-0000-1000-8000-00805f9b34fb" in scanner.extra["ble_service_uuids"]


def test_ble_scanner_no_java_returns_defaults(tmp_path):
    t, disc, auth, state, cmds, evts = BLEScanner(tmp_path).scan("com.example")
    assert t.type == TransportType.BLE
    assert cmds == []
    assert evts == []


def test_ble_scanner_write_only(tmp_path):
    _write_java(tmp_path, _JAVA_BLE_ONLY_WRITE, "BleWriter.java")
    _, _, _, _, commands, events = BLEScanner(tmp_path).scan("com.example")
    assert any(ep.cmd == "cmd" for ep in commands)
    # write-only char → command, not event
    uuids = {ep.cmd for ep in events}
    assert "cmd" not in uuids


def test_ble_scanner_notify_is_event(tmp_path):
    _write_java(tmp_path, _JAVA_BLE_WRITE_NOTIFY, "BleDevice.java")
    _, _, _, _, commands, events = BLEScanner(tmp_path).scan("com.example")
    assert any(ep.direction == Direction.TO_DEVICE for ep in commands)
    assert any(ep.direction == Direction.FROM_DEVICE for ep in events)


def test_ble_scanner_all_confidence_below_1(tmp_path):
    _write_java(tmp_path, _JAVA_BLE)
    _, _, _, _, commands, events = BLEScanner(tmp_path).scan("com.example")
    for ep in commands + events:
        assert ep.confidence < 1.0


def test_ble_scanner_no_ble_java_returns_empty(tmp_path):
    _write_java(tmp_path, _JAVA_NO_BLE, "NetworkClient.java")
    _, _, _, _, commands, events = BLEScanner(tmp_path).scan("com.example")
    assert commands == []
    assert events == []
