# SPDX-License-Identifier: MIT
"""BLE scanning of Kotlin-decompiled code: companion constants used across files."""

from __future__ import annotations

from pathlib import Path

from engine.extraction.ble_scanner import BLEScanner
from engine.ir.models import AuthType

_MANAGER = """package com.example.gate;
import android.bluetooth.BluetoothGatt;
import java.util.UUID;
public final class BleManager {
    public static final Companion INSTANCE = new Companion(null);
    private static final UUID GATE_SERVICE_UUID;
    private static final UUID NONCE_UUID;
    private static final UUID AUTHENTICATE_UUID;
    private static final UUID ACTION_UUID;
    static {
        UUID uuidFromString = UUID.fromString("00000100-0000-1000-8000-00805F9B34FB");
        NONCE_UUID = uuidFromString;
        UUID uuidFromString2 = UUID.fromString("00000101-0000-1000-8000-00805F9B34FB");
        AUTHENTICATE_UUID = uuidFromString2;
        UUID uuidFromString3 = UUID.fromString("6a7e6a7e-4929-42d0-0000-fcc5a35e13f1");
        GATE_SERVICE_UUID = uuidFromString3;
        UUID uuidFromString4 = UUID.fromString("00000106-0000-1000-8000-00805F9B34FB");
        ACTION_UUID = uuidFromString4;
    }
    public final void writeCharacteristic(BluetoothGatt gatt, UUID uuid, byte[] value) {
        gatt.writeCharacteristic(gatt.getService(GATE_SERVICE_UUID).getCharacteristic(uuid));
    }
}
"""

_SCREEN = """package com.example.gate;
public final class GateScreen {
    void open(BluetoothGatt gatt) {
        bleManager.readCharacteristic(gatt, BleManager.INSTANCE.getNONCE_UUID());
        bleManager.writeCharacteristic(gatt, BleManager.INSTANCE.getAUTHENTICATE_UUID(), sig);
        bleManager.writeCharacteristic(gatt, BleManager.INSTANCE.getACTION_UUID(), new byte[]{1});
    }
}
"""


def _scan(tmp_path: Path) -> BLEScanner:
    pkg = tmp_path / "sources" / "com" / "example" / "gate"
    pkg.mkdir(parents=True)
    (pkg / "BleManager.java").write_text(_MANAGER)
    (pkg / "GateScreen.java").write_text(_SCREEN)
    return BLEScanner(tmp_path)


def test_companion_constants_keep_their_names(tmp_path: Path) -> None:
    scanner = _scan(tmp_path)
    _, _, _, _, commands, events = scanner.scan("com.example.gate")

    names = {e.cmd for e in commands + events}
    assert not any(n.startswith("uuidFromString") for n in names)
    assert scanner.extra["ble_service_uuids"] == ["6a7e6a7e-4929-42d0-0000-fcc5a35e13f1"]


def test_access_found_through_wrapper_and_getters_in_other_file(tmp_path: Path) -> None:
    _, _, _, _, commands, events = _scan(tmp_path).scan("com.example.gate")

    assert {c.cmd for c in commands} == {"action", "authenticate"}
    assert {e.cmd for e in events} == {"nonce"}


def test_challenge_response_auth_detected(tmp_path: Path) -> None:
    _, _, auth, _, _, _ = _scan(tmp_path).scan("com.example.gate")

    assert auth.type is AuthType.CHALLENGE_RESPONSE
    assert auth.handshake_cmd == "authenticate"
