# SPDX-License-Identifier: MIT
"""Plain GATT devices: what the app writes and reads (P2-8b) and the entities (P5).

The Java fixture reproduces the decompiled BioLite FirePit app's shapes: Kotlin
companion UUID constants read through getters, a reused local "characteristic"
in every method, one-byte writers called with literals, a notify handler with a
branch per characteristic, and a scan list filtered on the advertised name.
"""
# ruff: noqa: E501 — the Java fixtures reproduce decompiler output line for line

from __future__ import annotations

from pathlib import Path

from engine.emitters import context, gatt
from engine.extraction.ble_scanner import BLEScanner, _uuid_to_cmd
from engine.ir.models import (
    AuthScheme,
    AuthType,
    ChallengeResponseProfile,
    DiscoveryType,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)

_SIG = "-0000-1000-8000-00805f9b34fb"

_CONSTANTS = f"""package com.example.pit.ble;
public final class BleConstants {{
    public static final Companion INSTANCE = new Companion(null);
    private static final UUID VENDOR_SERVICE_UUID;
    private static final UUID OTA_SERVICE_UUID;
    private static final UUID FAN_SPEED_CHARACTERISTIC_UUID;
    private static final UUID USB_OUT_CHARACTERISTIC_UUID;
    private static final UUID CHARGING_IN_CHARACTERISTIC_UUID;
    private static final UUID CURRENT_CHARACTERISTIC_UUID;
    private static final UUID BATTERY_LEVEL_CHARACTERISTIC_UUID;
    private static final UUID MANUFACTURER_NAME_CHARACTERISTIC_UUID;
    private static final UUID OTA_CONTROL_POINT;

    public static final class Companion {{
        public final UUID getFAN_SPEED_CHARACTERISTIC_UUID() {{ return BleConstants.FAN_SPEED_CHARACTERISTIC_UUID; }}
        public final UUID getUSB_OUT_CHARACTERISTIC_UUID() {{ return BleConstants.USB_OUT_CHARACTERISTIC_UUID; }}
        public final UUID getVENDOR_SERVICE_UUID() {{ return BleConstants.VENDOR_SERVICE_UUID; }}
    }}

    static {{
        UUID uuidFromString = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000001");
        VENDOR_SERVICE_UUID = uuidFromString;
        UUID uuidFromString2 = UUID.fromString("aaaaaaaa-0000-4000-8000-0000000000f0");
        OTA_SERVICE_UUID = uuidFromString2;
        UUID uuidFromString3 = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000002");
        FAN_SPEED_CHARACTERISTIC_UUID = uuidFromString3;
        UUID uuidFromString4 = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000003");
        USB_OUT_CHARACTERISTIC_UUID = uuidFromString4;
        UUID uuidFromString5 = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000004");
        CHARGING_IN_CHARACTERISTIC_UUID = uuidFromString5;
        UUID uuidFromString6 = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000005");
        CURRENT_CHARACTERISTIC_UUID = uuidFromString6;
        UUID uuidFromString7 = UUID.fromString("00002a19{_SIG}");
        BATTERY_LEVEL_CHARACTERISTIC_UUID = uuidFromString7;
        UUID uuidFromString8 = UUID.fromString("00002a29{_SIG}");
        MANUFACTURER_NAME_CHARACTERISTIC_UUID = uuidFromString8;
        UUID uuidFromString9 = UUID.fromString("aaaaaaaa-0000-4000-8000-0000000000f1");
        OTA_CONTROL_POINT = uuidFromString9;
    }}
}}
"""

_ACTIVITY = """package com.example.pit.screens;
public final class MainActivity extends AppCompatActivity {
    private final void onLevel(int i) {
        if (i == 0) {
            this.selectLevel(FanSpeedLevel.OFF);
        }
    }

    private final void onButtons() {
        writeFanSpeed(4);
        writeFanSpeed(3);
        writeFanSpeed(2);
        writeFanSpeed(1);
        writeFanSpeed(0);
        writeUsbOut(1);
        writeUsbOut(0);
    }

    public final void handleCharacteristicValue(UUID uuid, byte[] value) {
        if (Intrinsics.areEqual(uuid, BleConstants.INSTANCE.getMANUFACTURER_NAME_CHARACTERISTIC_UUID())) {
            Log.d(this.TAG, "Maker: ".concat(new String(value, Charsets.UTF_8)));
            return;
        }
        if (Intrinsics.areEqual(uuid, BleConstants.INSTANCE.getFAN_SPEED_CHARACTERISTIC_UUID())) {
            this.fanSpeed = value[0];
            return;
        }
        if (Intrinsics.areEqual(uuid, BleConstants.INSTANCE.getCHARGING_IN_CHARACTERISTIC_UUID())) {
            byte b = value[0];
            getSharedViewModel().setCharging(b != 0);
            return;
        }
        if (Intrinsics.areEqual(uuid, BleConstants.INSTANCE.getUSB_OUT_CHARACTERISTIC_UUID())) {
            Log.d(this.TAG, "USB out: " + ((int) value[0]));
            return;
        }
        if (Intrinsics.areEqual(uuid, BleConstants.INSTANCE.getCURRENT_CHARACTERISTIC_UUID())) {
            Log.d(this.TAG, "Current: " + UtilsKt.bytesToShortLE(value));
            return;
        }
        if (Intrinsics.areEqual(uuid, BleConstants.INSTANCE.getBATTERY_LEVEL_CHARACTERISTIC_UUID())) {
            this.batteryLevel = value[0];
            return;
        }
        if (Intrinsics.areEqual(uuid, BleConstants.INSTANCE.getOTA_CONTROL_POINT())) {
            Log.d(this.TAG, "Ota: ".concat(new String(value, Charsets.UTF_8)));
        }
    }

    public final void writeFanSpeed(int value) {
        byte[] bArr = {(byte) value};
        BluetoothGatt bluetoothGatt = this.manager.getBluetoothGatt();
        BluetoothGattService service = bluetoothGatt.getService(BleConstants.INSTANCE.getVENDOR_SERVICE_UUID());
        BluetoothGattCharacteristic characteristic = service.getCharacteristic(BleConstants.INSTANCE.getFAN_SPEED_CHARACTERISTIC_UUID());
        characteristic.setValue(bArr);
        bluetoothGatt.writeCharacteristic(characteristic);
    }

    public final void writeUsbOut(int value) {
        byte[] bArr = {(byte) value};
        BluetoothGatt bluetoothGatt = this.manager.getBluetoothGatt();
        BluetoothGattService service = bluetoothGatt.getService(BleConstants.INSTANCE.getVENDOR_SERVICE_UUID());
        BluetoothGattCharacteristic characteristic = service.getCharacteristic(BleConstants.INSTANCE.getUSB_OUT_CHARACTERISTIC_UUID());
        characteristic.setValue(bArr);
        bluetoothGatt.writeCharacteristic(characteristic);
    }

    public final void enableNotifications(BluetoothGattCharacteristic characteristic) {
        this.manager.getBluetoothGatt().setCharacteristicNotification(characteristic, true);
    }
}
"""

# Device list: classic discovery (no BLE classes), filtered on the advertised name.
_SCAN = """package com.example.pit.fragment;
public final class ScanDialogFragment extends DialogFragment {
    public void onReceive(Context context, Intent intent) {
        String name2 = bluetoothDevice.getName();
        if (StringsKt.contains$default((CharSequence) name2, (CharSequence) "PitPro", false, 2, (Object) null)) {
            this.adapter.addDevice(bluetoothDevice);
        }
    }
}
"""


def _apk(tmp_path: Path) -> Path:
    root = tmp_path / "sources" / "com" / "example" / "pit"
    for rel, src in (
        ("ble/BleConstants.java", _CONSTANTS),
        ("screens/MainActivity.java", _ACTIVITY),
        ("fragment/ScanDialogFragment.java", _SCAN),
    ):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(src)
    return tmp_path


def _scan(tmp_path: Path) -> tuple[BLEScanner, tuple]:  # type: ignore[type-arg]
    scanner = BLEScanner(_apk(tmp_path))
    return scanner, scanner.scan("com.example.pit")


def test_writes_resolve_through_getters_per_method(tmp_path: Path) -> None:
    scanner, _ = _scan(tmp_path)
    access = scanner.extra["ble_char_access"]

    assert access["fanSpeed"] == ["read", "write"]  # written, and decoded when read
    assert access["usbOut"] == ["read", "write"]
    # enableNotifications(characteristic) takes a parameter: the "characteristic"
    # bound in writeUsbOut belongs to that method and must not leak into it.
    assert "notify" not in access["usbOut"]


def test_writer_values_and_read_decoding(tmp_path: Path) -> None:
    scanner, (_, _, _, _, commands, _) = _scan(tmp_path)
    profiles = scanner.extra["ble_gatt"]

    assert profiles["fanSpeed"] == {
        "decode": "int8",
        "writer": "writeFanSpeed",
        "write_encoding": "uint8",
        "values": [0, 1, 2, 3, 4],
    }
    assert profiles["usbOut"]["values"] == [0, 1]
    assert profiles["chargingIn"]["decode"] == "bool"  # b = value[0]; … b != 0
    assert profiles["current"]["decode"] == "int16le"
    assert profiles["manufacturerName"]["decode"] == "utf8"
    fan = next(c for c in commands if c.cmd == "fanSpeed")
    assert fan.request_fields[0].enum_values == [0, 1, 2, 3, 4]


def test_discovery_from_name_filter(tmp_path: Path) -> None:
    _, (_, discovery, *_) = _scan(tmp_path)

    assert discovery.type is DiscoveryType.BLUETOOTH
    assert discovery.local_name == "PitPro"


def test_cmd_names_drop_characteristic_and_uuid_suffixes() -> None:
    assert _uuid_to_cmd("FAN_SPEED_CHARACTERISTIC_UUID", "x") == "fanSpeed"


def _ir(tmp_path: Path) -> ProtocolIR:
    scanner, (transport, discovery, auth, _, commands, events) = _scan(tmp_path)
    return ProtocolIR(
        apk_path="pit.apk",
        package_name="com.example.pit",
        app_name="Pit Pro",
        framework=Framework.NATIVE,
        transport=transport,
        discovery=discovery,
        auth=auth,
        state=StateSchema(),
        commands=commands,
        events=events,
        extra=scanner.extra,
    )


def test_entities_from_profile(tmp_path: Path) -> None:
    ctx = gatt.build(_ir(tmp_path), "pit")
    assert ctx is not None

    assert [(f["key"], f["speed_count"]) for f in ctx["fans"]] == [("fan_speed", 4)]
    assert [s["key"] for s in ctx["switches"]] == ["usb_out"]
    sensors = {s["key"]: s for s in ctx["sensors"]}
    assert set(sensors) == {"battery_level", "current"}
    assert sensors["battery_level"]["device_class"] == "battery"  # SIG 0x2A19
    assert sensors["current"]["unit"] is None  # the app shows none: none is guessed
    assert [b["key"] for b in ctx["binary_sensors"]] == ["charging_in"]
    assert ctx["device_info"] == {"manufacturer": f"00002a29{_SIG}"}
    assert ctx["local_name"] == "PitPro"
    # the OTA service is no discovery matcher, and OTA characteristics no entities
    assert ctx["service_uuids"] == ["aaaaaaaa-0000-4000-8000-000000000001"]
    assert not any("ota" in e["key"] for e in ctx["state"])
    assert ctx["platforms"] == ["binary_sensor", "fan", "sensor", "switch"]


def test_context_routes_to_gatt_path(tmp_path: Path) -> None:
    ctx = context.build(_ir(tmp_path))

    assert ctx["has_gatt"] and not ctx["has_challenge_auth"]


def test_not_gatt_for_other_transports_or_auth(tmp_path: Path) -> None:
    ir = _ir(tmp_path)

    http = ir.model_copy(update={"transport": TransportContract(type=TransportType.HTTP_REST)})
    assert gatt.build(http, "pit") is None
    authed = ir.model_copy(
        update={
            "auth": AuthScheme(
                type=AuthType.CHALLENGE_RESPONSE,
                challenge=ChallengeResponseProfile(challenge="nonce", proof="signature"),
            )
        }
    )
    assert gatt.build(authed, "pit") is None  # challenge-response devices have their own path
