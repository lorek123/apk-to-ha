# SPDX-License-Identifier: MIT
"""Tests for the framed command protocol scanner and codec (P2-8c).

The Java fixtures reproduce the shapes jadx produces for a vendor command SDK
(base command class, one class per command, a reply dispatcher, a token parser,
UUIDs in an asset config); the frames are the shapes a JBL Flip 6 sent back
(the MAC address is made up).
"""
# ruff: noqa: E501 — the Java fixtures reproduce decompiler output line for line

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from engine.emitters import context as emitter_context
from engine.emitters import framed as framed_emit
from engine.emitters import sdk_emitter
from engine.extraction import framed_codec as codec
from engine.extraction import framed_scanner
from engine.ir.models import (
    AuthScheme,
    AuthType,
    DiscoveryMechanism,
    DiscoveryType,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)
from engine.pipeline import _emit_blocker

_PKG = "com/example/sdk"

_SOURCES = {
    "command/BaseCommand.java": """package com.example.sdk.command;
public class BaseCommand implements Command {
    private byte command;
    private byte identifier;
    private byte[] payload;
    private LinkedList<Byte> responseCommands;

    public BaseCommand() {
        this.responseCommands = new LinkedList<>();
        this.identifier = (byte) -86;
        this.command = (byte) 17;
    }

    protected final LinkedList<Byte> getResponseCommands() {
        return this.responseCommands;
    }

    public final void setCommand(byte b) {
        this.command = b;
    }

    public final void setPayload(byte[] bArr) {
        this.payload = bArr;
    }

    public byte[] data() {
        byte[] bArr = {getIdentifier(), this.command, (byte) getPayloadLen()};
        byte[] bArr2 = this.payload;
        if (bArr2 == null) {
            return bArr;
        }
        byte[] bArr3 = new byte[bArr2.length + 3];
        System.arraycopy(bArr, 0, bArr3, 0, 3);
        System.arraycopy(bArr2, 0, bArr3, 3, bArr2.length);
        return bArr3;
    }
}
""",
    "utils/PacketFormat.java": """package com.example.sdk.utils;
public final class PacketFormat {
    public static final String BATTERY_STATUS = "44";
    public static final String DEVICE_NAME = "c1";
    public static final byte DISABLE_EQ_FEATURE = 18;
    public static final String MAC_ADDRESS_TOKEN_ID = "48";
    public static final String PRODUCT_ID = "42";
    public static final byte REP_EQ_MODE_SETTING = 98;
    public static final byte REP_VER = 66;
    public static final byte REQ_EQ_MODE_SETTING = 97;
    public static final byte REQ_VER = 65;
    public static final byte REQ_MFB_STATUS = 51;
    public static final byte RET_DEV_INFO = 18;
    public static final byte RET_MFB_STATUS = 52;
    public static final byte SET_EQ_MODE_SETTING = 99;
    public static final byte REQ_FEEDBACK_STATUS = 101;
    public static final byte REP_FEEDBACK_STATUS = 102;
    public static final byte SET_FEEDBACK_STATUS = 103;
    public static final byte SET_LIGHT_STATUS = 115;
}
""",
    "command/ReqVerCommand.java": """package com.example.sdk.command;
public final class ReqVerCommand extends BaseCommand {
    public ReqVerCommand() {
        setCommand(PacketFormat.REQ_VER);
        getResponseCommands().add(Byte.valueOf(PacketFormat.REP_VER));
        setPayload(null);
    }

    public BaseMessage onReceive(HmDevice device, Command receiveCommand) {
        if (receiveCommand.getCommand() == 66) {
            processFirmwareVersion(device, HexUtil.encodeHexStr(receiveCommand.getPayload()));
        }
        return null;
    }

    private final void processFirmwareVersion(HmDevice deviceModel, String content) {
        String version = formatVersion(content);
        deviceModel.setFirmwareVer(version);
    }

    private final String formatVersion(String content) {
        StringBuffer stringBuffer = new StringBuffer();
        int i = 0;
        while (i < content.length()) {
            int i2 = i + 2;
            stringBuffer.append(Integer.parseInt(content.substring(i, i2)));
            stringBuffer.append(".");
            i = i2;
        }
        return stringBuffer.toString();
    }
}
""",
    "command/ReqEQModeCommand.java": """package com.example.sdk.command;
public final class ReqEQModeCommand extends BaseCommand {
    public ReqEQModeCommand() {
        setCommand(PacketFormat.REQ_EQ_MODE_SETTING);
        getResponseCommands().add(Byte.valueOf(PacketFormat.REP_EQ_MODE_SETTING));
        setPayload(null);
    }
}
""",
    "command/SetEQModeCommand.java": """package com.example.sdk.command;
public final class SetEQModeCommand extends BaseCommand {
    public SetEQModeCommand(byte b) {
        setCommand(PacketFormat.SET_EQ_MODE_SETTING);
        getResponseCommands().add((byte) 0);
        setPayload(new byte[]{b});
    }

    @Override
    public BaseMessage onReceive(HmDevice device, Command receivedCommand) {
        byte[] payload;
        BaseMessage baseMessage = new BaseMessage();
        if (receivedCommand.getCommand() == 0 && (payload = receivedCommand.getPayload()) != null && payload.length > 1 && 99 == payload[0] && payload[1] == 0) {
            getResponseCommands().removeFirst();
            byte[] payload2 = getPayload();
            if (payload2 != null) {
                device.setEqMode(payload2[0]);
            }
        }
        return baseMessage;
    }
}
""",
    "command/ReqFeedbackToneCommand.java": """package com.example.sdk.command;
public final class ReqFeedbackToneCommand extends BaseCommand {
    public ReqFeedbackToneCommand() {
        setCommand(PacketFormat.REQ_FEEDBACK_STATUS);
        getResponseCommands().add(Byte.valueOf(PacketFormat.REP_FEEDBACK_STATUS));
    }
}
""",
    "command/SetFeedbackToneCommand.java": """package com.example.sdk.command;
public final class SetFeedbackToneCommand extends BaseCommand {
    public SetFeedbackToneCommand(byte b) {
        setCommand(PacketFormat.SET_FEEDBACK_STATUS);
        setPayload(new byte[]{b});
    }

    @Override
    public BaseMessage onReceive(HmDevice device, Command receivedCommand) {
        BaseMessage baseMessage = new BaseMessage();
        byte[] payload = receivedCommand.getPayload();
        if (receivedCommand.getCommand() == 0 && payload != null && payload.length > 1 && 103 == payload[0] && payload[1] == 0) {
            byte[] payload2 = getPayload();
            if (payload2 != null) {
                device.setFeedbackToneStatus(payload2[0]);
            }
        }
        return baseMessage;
    }
}
""",
    "command/SetLightStatusCommand.java": """package com.example.sdk.command;
public final class SetLightStatusCommand extends BaseCommand {
    public SetLightStatusCommand(byte b) {
        setCommand(PacketFormat.SET_LIGHT_STATUS);
        setPayload(new byte[]{b});
    }

    @Override
    public BaseMessage onReceive(HmDevice device, Command receivedCommand) {
        byte[] payload = receivedCommand.getPayload();
        if (receivedCommand.getCommand() == 0 && payload != null && 21 == payload[0] && payload[1] == 0) {
            device.setLightStatus(getPayload()[0]);
        }
        return new BaseMessage();
    }
}
""",
    "control/DeviceControl.java": """package com.example.sdk.control;
public interface DeviceControl {
    void setFeedbackToneStatus(HmDevice device, byte status, DeviceListener listener);
}
""",
    "control/DeviceControlImpl.java": """package com.example.sdk.control;
public final class DeviceControlImpl implements DeviceControl {
    @Override
    public void setFeedbackToneStatus(HmDevice device, byte status, DeviceListener listener) {
        sendCommand(device, new SetFeedbackToneCommand(status), listener);
    }

    public final void sendEQModeCmd(byte eqMode) {
        sendCommand(this.device, new SetEQModeCommand(eqMode), null);
    }

    public final void refreshLights() {
        sendCommand(this.device, new SetLightStatusCommand(this.brightStatus), null);
    }

    public final void lightsOn() {
        sendCommand(this.device, new SetLightStatusCommand((byte) 1), null);
    }
}
""",
    "ui/FeedbackCard.java": """package com.example.ui;
public final class FeedbackCard {
    public void onActionOn() {
        this.control.setFeedbackToneStatus(this.device, (byte) 1, null);
    }

    public void onActionOff() {
        this.control.setFeedbackToneStatus(this.device, (byte) 0, null);
    }
}
""",
    "ui/SoundModeActivity.java": """package com.example.ui;
public final class SoundModeActivity {
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[ClickEventType.values().length];
            try {
                iArr[ClickEventType.ACTION_INDOOR.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[ClickEventType.ACTION_OUTDOOR.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    public void onAction(ClickEventType actionName) {
        switch (actionName == null ? -1 : WhenMappings.$EnumSwitchMapping$0[actionName.ordinal()]) {
            case 1:
                this.control.sendEQModeCmd((byte) 0);
                break;
            case 2:
                this.control.sendEQModeCmd((byte) 1);
                break;
        }
    }
}
""",
    "command/ReqMFBCommand.java": """package com.example.sdk.command;
public final class ReqMFBCommand extends BaseCommand {
    public ReqMFBCommand() {
        setCommand(PacketFormat.REQ_MFB_STATUS);
        getResponseCommands().add(Byte.valueOf(PacketFormat.RET_MFB_STATUS));
    }
}
""",
    "command/ReqBatteryCommand.java": """package com.example.sdk.command;
public final class ReqBatteryCommand extends BaseCommand {
    public ReqBatteryCommand(int i) {
        setCommand((byte) 19);
        setPayload(new byte[]{(byte) (i == -1 ? 0 : i), (byte) Integer.parseInt(PacketFormat.BATTERY_STATUS, CharsKt.checkRadix(16))});
        getResponseCommands().add((byte) 18);
    }
}
""",
    "command/GetDevInfoCommand.java": """package com.example.sdk.command;
public final class GetDevInfoCommand extends BaseCommand {
    public GetDevInfoCommand() {
        setCommand((byte) 17);
        getResponseCommands().add(Byte.valueOf((byte) Integer.parseInt("c1", CharsKt.checkRadix(16))));
        getResponseCommands().add(Byte.valueOf((byte) Integer.parseInt(PacketFormat.PRODUCT_ID, CharsKt.checkRadix(16))));
    }
}
""",
    "command/ReqAuthenticationCommand.java": """package com.example.sdk.command;
public final class ReqAuthenticationCommand extends BaseCommand {
    public ReqAuthenticationCommand(AuthenticationAction authentication, int i) {
        super.setCommand((byte) -15);
        setPayload(new byte[]{(byte) (authentication.ordinal() + 1), (byte) i});
    }
}
""",
    "command/CommandProcessor.java": """package com.example.sdk.command;
public final class CommandProcessor {
    public final BaseMessage processCommand(HmDevice device, Command receiveCommand, Command sentCommand) {
        String strEncodeHexStr = HexUtil.encodeHexStr(receiveCommand.getPayload());
        byte command = receiveCommand.getCommand();
        if (command == 18) {
            processDeviceInfoRes(device, strEncodeHexStr);
            return null;
        }
        if (command == 98 || command == 100) {
            device.setEqMode(Byte.parseByte(strEncodeHexStr, CharsKt.checkRadix(16)));
            return null;
        }
        if (command == 102) {
            device.setFeedbackToneStatus(Byte.parseByte(strEncodeHexStr, CharsKt.checkRadix(16)));
            return null;
        }
        return null;
    }

    private final void processDeviceInfoRes(HmDevice deviceModel, String unprocessedPayload) {
        String[] strArrRetDevInfoTokenIds = retDevInfoTokenIds(14, PacketFormat.MAC_ADDRESS_TOKEN_ID, unprocessedPayload);
        String[] strArrRetDevInfoTokenIds5 = retDevInfoTokenIds(4, PacketFormat.BATTERY_STATUS, strArrRetDevInfoTokenIds[1]);
        String str5 = strArrRetDevInfoTokenIds5[0];
        String[] strArrRetDevInfoTokenIds7 = retDevInfoTokenIds(6, PacketFormat.PRODUCT_ID, strArrRetDevInfoTokenIds5[1]);
        String str8 = strArrRetDevInfoTokenIds7[1];
        if (str5 != null) {
            int hexStringToInt = HexUtil.parseHexStringToInt(str5, PacketFormat.BATTERY_STATUS);
            BatteryInfo batteryInfo = new BatteryInfo();
            if (hexStringToInt >= 128) {
                int i2 = hexStringToInt - 128;
                batteryInfo.setMasterLevel(i2);
                batteryInfo.setMasterCharging(true);
            } else {
                batteryInfo.setMasterLevel(hexStringToInt);
                batteryInfo.setMasterCharging(false);
            }
        }
        if (str8 != null) {
            String name = retrieveDevName("c1", str8);
            if (name != null) {
                deviceModel.setDeviceName(HexUtil.hexStringToString(name));
            }
        }
    }

    private final String retrieveDevName(String tokenID, String unprocessedPayload) {
        int iIndexOf = unprocessedPayload.indexOf(tokenID);
        int i2 = iIndexOf + 4;
        String strSubstring = unprocessedPayload.substring(iIndexOf + 2, i2);
        return unprocessedPayload.substring(i2, (Integer.valueOf(strSubstring, 16).intValue() * 2) + i2);
    }

    private final String[] retDevInfoTokenIds(int tokenIDBytesLength, String tokenID, String unprocessedPayload) {
        return new String[2];
    }
}
""",
    "connect/GattControllerImpl.java": """package com.example.sdk.connect;
public final class GattControllerImpl {
    public final void doServicesDiscovered(String macKey, BluetoothGatt gatt) {
        UUID uuidFromString2 = UUID.fromString(DeviceUtils.getAppConfig().getRxUUID());
        UUID uuidFromString3 = UUID.fromString(DeviceUtils.getAppConfig().getTxUUID());
        UUID uuidFromString5 = UUID.fromString(DeviceUtils.getAppConfig().getBleRxTxUUID());
        BluetoothGattService service = gatt.getService(uuidFromString5);
        BluetoothGattCharacteristic characteristic2 = service.getCharacteristic(uuidFromString2);
        BluetoothGattCharacteristic characteristic3 = service.getCharacteristic(uuidFromString3);
        gatt.setCharacteristicNotification(characteristic2, true);
        this.characteristicMap.put(macKey, characteristic3);
    }
}
""",
    "scan/BroadcastParser.java": """package com.example.sdk.scan;
public final class BroadcastParser {
    public Map<String, String> parse(ScanRecord record) {
        byte[] manufacturerSpecificData = record.getManufacturerSpecificData(87);
        return null;
    }
}
""",
}

_APP_CONFIG = {
    "maxReconnectCount": 3,
    "rxUUID": "65786365-6C70-6F69-6E74-2E636F6D0001",
    "txUUID": "65786365-6C70-6F69-6E74-2E636F6D0002",
    "bleRxTxUUID": "65786365-6C70-6F69-6E74-2E636F6D0000",
    "descriptor": "00002902-0000-1000-8000-00805F9B34FB",
}
_PRODUCTS = {
    "products": [
        {
            "deviceName": "Speaker A",
            "pid": "20AB",
            "protocol": "PROTOCOL_BLE",
            "features": ["FEEDBACK_SUPPORT"],
        },
        {"deviceName": "Speaker B", "pid": "204f", "protocol": "PROTOCOL_GATT_BR_EDR"},
    ]
}


@pytest.fixture(scope="module")
def proto(tmp_path_factory: pytest.TempPathFactory) -> framed_scanner.FramedProtocol:
    root = tmp_path_factory.mktemp("apk")
    files = []
    for rel, text in _SOURCES.items():
        p = root / "sources" / _PKG / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        files.append(p)
    assets = root / "resources" / "assets"
    assets.mkdir(parents=True)
    (assets / "AppConfig.json").write_text(json.dumps(_APP_CONFIG))
    (assets / "products.json").write_text(json.dumps(_PRODUCTS))
    result = framed_scanner.scan(root, files)
    assert result is not None
    return result


def _cmd(proto: framed_scanner.FramedProtocol, name: str) -> dict[str, Any]:
    return next(c for c in proto.commands if c["name"] == name)


def test_frame_layout_from_the_serialiser(proto: framed_scanner.FramedProtocol) -> None:
    assert proto.base_class == "BaseCommand"
    assert proto.frame == [
        {"kind": "const", "value": 0xAA},  # the identifier field's default, (byte) -86
        {"kind": "opcode"},
        {"kind": "length"},
        {"kind": "payload"},
    ]


def test_commands_opcodes_payloads_and_replies(proto: framed_scanner.FramedProtocol) -> None:
    ver = _cmd(proto, "ReqVer")
    assert (ver["opcode"], ver["payload"], ver["replies"], ver["kind"]) == (
        0x41,
        [],
        [0x42],
        "request",
    )

    eq = _cmd(proto, "SetEQMode")
    assert eq["opcode"] == 0x63 and eq["kind"] == "set"
    assert eq["payload"] == [{"param": "b", "type": "byte"}]
    assert eq["params"] == [{"name": "b", "type": "byte"}]

    battery = _cmd(proto, "ReqBattery")
    # (byte) (i == -1 ? 0 : i) → the parameter, defaulting to 0; the token id as a literal
    assert battery["payload"] == [{"param": "i", "type": "int", "default": 0}, {"value": 0x44}]


def test_token_id_reply_lists_become_the_token_reply(proto: framed_scanner.FramedProtocol) -> None:
    # GetDevInfo lists the tokens it expects (c1, 42), not opcodes; 0x42 is also REP_VER.
    assert _cmd(proto, "GetDevInfo")["replies"] == [0x12]


def test_unresolved_payloads_are_marked_not_guessed(proto: framed_scanner.FramedProtocol) -> None:
    auth = _cmd(proto, "ReqAuthentication")
    assert auth["opcode"] == 0xF1
    assert not auth["complete"]
    assert {"unknown": "(byte) (authentication.ordinal() + 1)"} in auth["payload"]


def test_settings_ack_and_changed_field(proto: framed_scanner.FramedProtocol) -> None:
    tone = _cmd(proto, "SetFeedbackTone")
    assert tone["ack"] == {"opcode": 0, "ok": 0}
    assert tone["field"] == "feedback_tone_status"
    assert _cmd(proto, "SetEQMode")["field"] == "eq_mode"
    # its ack test is for another opcode (21), so it isn't this command's ack
    assert "ack" not in _cmd(proto, "SetLightStatus")


def test_setting_values_traced_through_wrappers_with_ui_labels(
    proto: framed_scanner.FramedProtocol,
) -> None:
    # onActionOn/Off → FeedbackCard → DeviceControl.setFeedbackToneStatus (3rd arg)
    # → new SetFeedbackToneCommand(status); the interface declaration isn't a call.
    tone = _cmd(proto, "SetFeedbackTone")
    assert (tone["values"], tone["values_complete"]) == ([0, 1], True)
    assert tone["value_labels"] == {"0": "off", "1": "on"}
    # case 1/2 of a `when` over ClickEventType.ACTION_INDOOR / ACTION_OUTDOOR
    eq = _cmd(proto, "SetEQMode")
    assert eq["value_labels"] == {"0": "indoor", "1": "outdoor"}


def test_setting_values_from_fields_are_not_guessed(proto: framed_scanner.FramedProtocol) -> None:
    light = _cmd(proto, "SetLightStatus")  # (byte) 1 in one place, this.brightStatus in another
    assert (light["values"], light["values_complete"]) == ([1], False)


def test_reply_decoders(proto: framed_scanner.FramedProtocol) -> None:
    replies = {r["opcode"]: r for r in proto.replies}
    assert replies[0x12] == {"opcode": 0x12, "decode": "tokens"}
    assert replies[0x62] == {"opcode": 0x62, "decode": "uint8", "field": "eq_mode"}
    assert replies[0x64]["field"] == "eq_mode"  # the "changed" notification, same field
    assert replies[0x42] == {"opcode": 0x42, "decode": "version", "field": "firmware_version"}


def test_tokens(proto: framed_scanner.FramedProtocol) -> None:
    tokens = {t["id"]: t for t in proto.tokens}
    assert tokens[0x44] == {
        "id": 0x44,
        "name": "battery_status",
        "size": 1,
        "encoding": "level_charging_bit7",
    }
    assert tokens[0x48]["name"] == "mac_address" and tokens[0x48]["size"] == 6
    assert tokens[0x42]["size"] == 2
    assert tokens[0xC1] == {"id": 0xC1, "name": "device_name", "size": None, "encoding": "utf8"}


def test_opcode_names_prefer_constants_used_as_opcodes(
    proto: framed_scanner.FramedProtocol,
) -> None:
    # RET_DEV_INFO and DISABLE_EQ_FEATURE are both 18; only RET_ shares a prefix with used names.
    assert proto.opcode_names[0x12] == "RET_DEV_INFO"
    assert proto.opcode_names[0x41] == "REQ_VER"


def test_transport_uuids_from_asset_config(proto: framed_scanner.FramedProtocol) -> None:
    assert proto.transport == {
        "source": "assets/AppConfig.json",
        "service": "65786365-6c70-6f69-6e74-2e636f6d0000",
        "notify": "65786365-6c70-6f69-6e74-2e636f6d0001",  # rxUUID: the app *receives* on it
        "write": "65786365-6c70-6f69-6e74-2e636f6d0002",
        "keys": {"notify": "rxUUID", "write": "txUUID"},
    }


def test_models_and_manufacturer_ids(proto: framed_scanner.FramedProtocol) -> None:
    assert proto.models == {
        "204f": {"name": "Speaker B", "protocol": "PROTOCOL_GATT_BR_EDR"},
        "20ab": {"name": "Speaker A", "protocol": "PROTOCOL_BLE", "features": ["FEEDBACK_SUPPORT"]},
    }
    assert proto.manufacturer_ids == [87]


def test_endpoints(proto: framed_scanner.FramedProtocol) -> None:
    commands, events = framed_scanner.endpoints(proto)
    eq = next(c for c in commands if c.cmd == "SetEQMode")
    assert [f.name for f in eq.request_fields] == ["b"]
    assert next(c for c in commands if c.cmd == "ReqAuthentication").confidence < 0.7
    assert {e.cmd for e in events} >= {"RET_DEV_INFO", "REP_EQ_MODE_SETTING", "REP_VER"}


def test_no_frame_serialiser_means_no_framed_protocol(tmp_path: Path) -> None:
    p = tmp_path / "sources" / "A.java"
    p.parent.mkdir(parents=True)
    p.write_text("public class A { private byte[] payload; }")
    assert framed_scanner.scan(tmp_path, [p]) is None


# ── codec ─────────────────────────────────────────────────────────────────────

_FRAME: list[dict[str, Any]] = [
    {"kind": "const", "value": 0xAA},
    {"kind": "opcode"},
    {"kind": "length"},
    {"kind": "payload"},
]
_TOKENS = {
    0x42: {"id": 0x42, "name": "product_id", "size": 2, "encoding": "hex"},
    0x44: {"id": 0x44, "name": "battery_status", "size": 1, "encoding": "level_charging_bit7"},
    0x48: {"id": 0x48, "name": "mac_address", "size": 6, "encoding": "hex"},
    0xC1: {"id": 0xC1, "name": "device_name", "size": None, "encoding": "utf8"},
}


def test_encode_requests() -> None:
    battery = {"name": "ReqBattery", "payload": [{"param": "i", "default": 0}, {"value": 0x44}]}
    assert codec.encode(_FRAME, 0x13, codec.command_payload(battery)) == bytes.fromhex("aa13020044")
    assert codec.encode(_FRAME, 0x41) == bytes.fromhex("aa4100")
    eq = {"name": "SetEQMode", "payload": [{"param": "b"}]}
    assert codec.encode(_FRAME, 0x63, codec.command_payload(eq, {"b": 2})) == bytes.fromhex(
        "aa630102"
    )
    with pytest.raises(ValueError, match="no value for b"):
        codec.command_payload(eq)


def test_frames_split_and_resync() -> None:
    data = bytes.fromhex("00aa620103aa4100")  # noise, EQ reply, empty frame
    assert list(codec.frames(_FRAME, data)) == [(0x62, b"\x03"), (0x41, b"")]


def test_device_info_one_token_per_frame() -> None:
    # Classic-link models answer with one token per frame.
    assert codec.decode_tokens(bytes.fromhex("004450"), _TOKENS) == {
        "device_index": 0,
        "battery_status": 80,
        "battery_status_charging": False,
    }
    name = bytes.fromhex("00c1094a424c204c6f726b61")
    assert codec.decode_tokens(name, _TOKENS)["device_name"] == "JBL Lorka"


def test_device_info_concatenated_tokens_and_charging_bit() -> None:
    payload = bytes.fromhex("00c10341424348a1b2c3d4e5f644d542204f")
    assert codec.decode_tokens(payload, _TOKENS) == {
        "device_index": 0,
        "device_name": "ABC",
        "mac_address": "a1b2c3d4e5f6",
        "battery_status": 85,  # 0xd5 = charging bit + 85
        "battery_status_charging": True,
        "product_id": "204f",
    }


def test_unknown_token_stops_parsing() -> None:
    # Its length is unknown, so nothing after it can be read safely.
    assert codec.decode_tokens(bytes.fromhex("004afd984450"), _TOKENS) == {"device_index": 0}


def test_reply_decoders_codec() -> None:
    assert codec.decode_reply({"decode": "uint8", "field": "eq_mode"}, b"\x00", {}) == {
        "eq_mode": 0
    }
    version = {"decode": "version", "field": "firmware_version"}
    # As the app formats it: each byte's hex digits as a decimal number.
    assert codec.decode_reply(version, bytes.fromhex("00060906"), {}) == {
        "firmware_version": "0.6.9.6"
    }
    assert codec.decode_reply(version, bytes.fromhex("10"), {}) == {"firmware_version": "10"}


def test_emit_is_blocked_without_an_entity_to_back() -> None:
    commands, events = framed_scanner.endpoints(
        framed_scanner.FramedProtocol(
            frame=_FRAME,
            commands=[
                {
                    "name": "ReqVer",
                    "class": "ReqVerCommand",
                    "opcode": 0x41,
                    "payload": [],
                    "params": [],
                    "replies": [0x42],
                    "kind": "request",
                    "complete": True,
                }
            ],
        )
    )
    ir = ProtocolIR(
        apk_path="a.apk",
        package_name="com.example",
        app_name="X",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.BLE),
        discovery=DiscoveryMechanism(type=DiscoveryType.BLUETOOTH, manufacturer_ids=[87]),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(),
        commands=commands,
        events=events,
        extra={"framed": {}},
    )
    blocker = _emit_blocker(ir)
    assert blocker is not None and blocker[0] == "unsupported-transport"
    assert "no entity" in blocker[1]


# ── emission ──────────────────────────────────────────────────────────────────


def _ir(proto: framed_scanner.FramedProtocol) -> ProtocolIR:
    commands, events = framed_scanner.endpoints(proto)
    return ProtocolIR(
        apk_path="speaker.apk",
        package_name="com.example.speaker",
        app_name="Speaker",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.BLE),
        discovery=DiscoveryMechanism(
            type=DiscoveryType.BLUETOOTH, manufacturer_ids=proto.manufacturer_ids
        ),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(),
        commands=commands,
        events=events,
        extra={"framed": framed_scanner.to_extra(proto)},
    )


def test_entities_from_extraction(proto: framed_scanner.FramedProtocol) -> None:
    ctx = framed_emit.build(_ir(proto), "speaker")
    assert ctx is not None

    assert [(s["key"], s["field"]) for s in ctx["sensors"]] == [("battery", "battery_status")]
    assert [b["field"] for b in ctx["binary_sensors"]] == ["battery_status_charging"]
    [tone] = ctx["switches"]
    assert (tone["key"], tone["on"], tone["off"], tone["read"]) == (
        "feedback_tone",
        1,
        0,
        "ReqFeedbackTone",
    )
    [eq] = ctx["selects"]
    assert (eq["key"], eq["options"]) == ("eq_mode", {0: "indoor", 1: "outdoor"})
    assert {r["name"] for r in ctx["poll"]} == {"ReqBattery", "ReqEQMode", "ReqFeedbackTone"}
    assert ctx["info_request"]["name"] == "GetDevInfo"
    assert ctx["version_request"]["name"] == "ReqVer"
    assert {u["cmd"]: u["reason"] for u in ctx["unmapped"]}["SetLightStatus"] == (
        "doesn't change one device field"
    )
    assert ctx["platforms"] == ["binary_sensor", "select", "sensor", "switch"]
    assert _emit_blocker(_ir(proto)) is None


def test_classic_bluetooth_models_are_marked(proto: framed_scanner.FramedProtocol) -> None:
    ctx = framed_emit.build(_ir(proto), "speaker")
    assert ctx is not None

    assert ctx["models"]["20ab"] == {"name": "Speaker A", "ble": True}
    assert ctx["models"]["204f"] == {"name": "Speaker B", "ble": False}
    assert ctx["unsupported_models"] == ["Speaker B"]


def test_unnamed_setting_values_get_no_entity(proto: framed_scanner.FramedProtocol) -> None:
    ir = _ir(proto)
    framed = ir.extra["framed"]
    for c in framed["commands"]:
        c.pop("value_labels", None)
    ctx = framed_emit.build(ir, "speaker")
    assert ctx is not None

    assert not ctx["switches"] and not ctx["selects"]
    reasons = {u["cmd"]: u["reason"] for u in ctx["unmapped"]}
    assert reasons["SetFeedbackTone"] == "the app doesn't name its values"


@pytest.fixture
def generated(proto: framed_scanner.FramedProtocol, tmp_path: Path) -> Any:
    """The generated SDK's protocol module (pure Python, imported from the emitted tree)."""
    ctx = emitter_context.build(_ir(proto))
    pkg = sdk_emitter.emit(ctx, tmp_path)
    spec = importlib.util.spec_from_file_location("generated_protocol", pkg / "protocol.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    del sys.modules[spec.name]


def test_generated_codec_agrees_with_reference(
    proto: framed_scanner.FramedProtocol, generated: Any
) -> None:
    tokens = {t["id"]: t for t in proto.tokens}
    payloads = [
        bytes.fromhex("0044d0"),  # charging, 80 %
        bytes.fromhex("0042204f44500107") + b"\xc1\x04Lorka",
        bytes.fromhex("01445a"),  # the other speaker of a pair
    ]
    for payload in payloads:
        assert generated.decode_tokens(payload) == codec.decode_tokens(payload, tokens)
    version = {"decode": "version", "field": "firmware_version"}
    assert generated.decode(0x42, bytes.fromhex("00060906")) == codec.decode_reply(
        version, bytes.fromhex("00060906"), tokens
    )
    battery = next(c for c in proto.commands if c["name"] == "ReqBattery")
    req = next(r for r in generated.POLL if r.name == "ReqBattery")
    assert generated.encode(req.opcode, req.payload) == codec.encode(
        proto.frame, battery["opcode"], codec.command_payload(battery)
    )
    data = codec.encode(proto.frame, 0x62, b"\x01") + codec.encode(proto.frame, 0x41, b"")
    assert list(generated.frames(b"\x00" + data)) == list(codec.frames(proto.frame, data))


async def test_generated_session_reads_and_applies(generated: Any) -> None:
    status = {"ack": 0}

    async def write(frame: bytes) -> None:
        (opcode, _), *_ = generated.frames(frame)
        replies = {
            0x13: (0x12, bytes.fromhex("01445a")),  # the paired speaker answers first
            0x61: (0x62, b"\x01"),
            0x65: (0x66, b"\x00"),
        }
        if opcode in replies:
            if opcode == 0x13:
                session.feed(generated.encode(*replies[0x13]))
                session.feed(generated.encode(0x12, bytes.fromhex("0044d0")))
            else:
                session.feed(generated.encode(*replies[opcode]))
        elif opcode == 0x67:
            session.feed(generated.encode(0x00, bytes([0x67, status["ack"]])))

    session = generated.Session(write)
    generated.REPLY_TIMEOUT = 0.05

    state = await session.read_state()
    assert state == {
        "battery_status": 80,
        "battery_status_charging": True,
        "eq_mode": 1,
        "feedback_tone_status": 0,
    }
    await session.apply("feedback_tone", 1)
    status["ack"] = 1
    with pytest.raises(generated.RejectedError):
        await session.apply("feedback_tone", 0)
    with pytest.raises(ValueError):
        await session.apply("feedback_tone", 7)
    with pytest.raises(generated.ProtocolError, match="no acknowledgement"):
        await session.apply("eq_mode", 0)  # the fake never acknowledges this one
