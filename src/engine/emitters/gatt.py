# SPDX-License-Identifier: MIT
"""P5 — Plain GATT devices (BLE, no authentication): entities from the GATT profile.

Uses what the BLE scanner learned from the app (ble_gatt: decoding, writers and
the values they write) plus the Bluetooth SIG's standard characteristics:

  fan            a one-byte writer whose values are 0..N (N ≥ 2, 0 = off) on a
                 fan/speed characteristic the app also reads back
  switch         a one-byte writer of 0/1 that the app reads back
  sensor         a characteristic the app decodes as a number (or a standard one)
  binary_sensor  a characteristic the app reads as a flag (byte != 0)
  device info    Device Information strings (manufacturer, model, firmware)

Firmware-update (OTA/DFU) characteristics never become entities, and anything
the app doesn't decode is left out rather than guessed.
"""

from __future__ import annotations

import re
from typing import Any

from ..ir.models import DiscoveryType, ProtocolIR, TransportType

_SIG = "-0000-1000-8000-00805f9b34fb"
# Standard characteristics: uuid → (key, how to use it)
_STANDARD_SENSORS = {
    f"00002a19{_SIG}": {
        "key": "battery_level",
        "decode": "uint8",
        "device_class": "battery",
        "unit": "%",
        "state_class": "measurement",
    },
}
_DEVICE_INFO = {
    f"00002a29{_SIG}": "manufacturer",
    f"00002a24{_SIG}": "model",
    f"00002a26{_SIG}": "sw_version",
    f"00002a27{_SIG}": "hw_version",
}
_SKIP = re.compile(r"ota|dfu|firmware|bootload|system_?id", re.IGNORECASE)
_FAN_NAME = re.compile(r"fan|speed|blower", re.IGNORECASE)
_NUMERIC = {"int8", "uint8", "int16le", "uint16le"}
# Writer method → entity key: writeUsbChargeOut → usb_charge_out,
# writeFanSpeedToFirepit → fan_speed.
_WRITER = re.compile(r"^(?:write|set|send|update)([A-Z]\w*?)(?:To[A-Z]\w*)?$")
# Test values a fake device starts with, per decoding.
_SAMPLE_BYTES = {
    "int8": "07",
    "uint8": "50",
    "int16le": "2c01",
    "uint16le": "2c01",
    "bool": "01",
    "utf8": "54657374",  # "Test"
}
_SAMPLE_STATE = {"int8": "7", "uint8": "80", "int16le": "300", "uint16le": "300", "bool": "on"}


def _snake(name: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def _human(key: str) -> str:
    text = key.replace("_", " ")
    text = re.sub(r"\b(usb|led|ble|ota)\b", lambda m: m.group(1).upper(), text)
    return text[0].upper() + text[1:]


def build(ir: ProtocolIR, domain: str) -> dict[str, Any] | None:
    """Template context for a plain GATT device, or None if this isn't one."""
    if ir.transport.type != TransportType.BLE or ir.auth.challenge is not None:
        return None
    uuids: dict[str, str] = ir.extra.get("ble_char_uuids", {})
    access: dict[str, list[str]] = ir.extra.get("ble_char_access", {})
    profiles: dict[str, dict[str, Any]] = ir.extra.get("ble_gatt", {})
    if not uuids:
        return None

    fans: list[dict[str, Any]] = []
    switches: list[dict[str, Any]] = []
    sensors: list[dict[str, Any]] = []
    binary_sensors: list[dict[str, Any]] = []
    device_info: dict[str, str] = {}
    unmapped: list[dict[str, str]] = []
    used_keys: set[str] = set()

    def key_for(cmd: str, writer: str | None) -> str:
        m = _WRITER.match(writer or "")
        key = _snake(m.group(1)) if m else _snake(cmd)
        while key in used_keys:
            key += "_2"
        used_keys.add(key)
        return key

    for cmd, uuid in uuids.items():
        uuid = uuid.lower()
        profile = profiles.get(cmd, {})
        readable = "read" in access.get(cmd, []) or "notify" in access.get(cmd, [])
        decode = profile.get("decode")
        values: list[int] = profile.get("values") or []
        if _SKIP.search(cmd):
            continue
        if uuid in _DEVICE_INFO:
            device_info[_DEVICE_INFO[uuid]] = uuid
            continue
        if profile.get("write_encoding") == "uint8" and values:
            if not (readable and decode in _NUMERIC | {"bool"}):
                unmapped.append({"cmd": cmd, "reason": "write-only: state can't be shown"})
                continue
            contiguous = values == list(range(values[-1] + 1))
            if contiguous and values[-1] >= 2 and _FAN_NAME.search(cmd):
                key = key_for(cmd, profile.get("writer"))
                fans.append(
                    {
                        "key": key,
                        "cmd": cmd,
                        "uuid": uuid,
                        "speed_count": values[-1],
                        "decode": decode,
                    }
                )
            elif values == [0, 1]:
                key = key_for(cmd, profile.get("writer"))
                switches.append({"key": key, "cmd": cmd, "uuid": uuid, "decode": decode})
            else:
                unmapped.append({"cmd": cmd, "reason": f"writes {values}: no matching entity"})
            continue
        if uuid in _STANDARD_SENSORS:
            spec = _STANDARD_SENSORS[uuid]
            key = spec["key"]
            used_keys.add(key)
            sensors.append({**spec, "cmd": cmd, "uuid": uuid})
            continue
        if not readable or decode is None:
            continue
        if decode == "bool":
            key = key_for(cmd, None)
            binary_sensors.append({"key": key, "cmd": cmd, "uuid": uuid, "decode": decode})
        elif decode in _NUMERIC:
            sensors.append(
                {
                    "key": key_for(cmd, None),
                    "cmd": cmd,
                    "uuid": uuid,
                    "decode": decode,
                    "device_class": None,  # the app shows no unit: none is guessed
                    "unit": None,
                    "state_class": "measurement",
                }
            )

    entities = fans + switches + sensors + binary_sensors
    if not entities:
        return None
    for e in entities:
        e["name"] = _human(e["key"])
        e["const"] = e["key"].upper() + "_UUID"
        e["sample_hex"] = _SAMPLE_BYTES[e["decode"]]
        e["sample_state"] = _SAMPLE_STATE.get(e["decode"])
    for e in fans:  # level 2 of N, as the fake device reports it
        e["sample_hex"], e["sample_state"] = "02", "on"
        e["sample_percentage"] = 2 * 100 // e["speed_count"]
    for e in switches:
        e["sample_hex"], e["sample_state"] = "01", "on"
    discovery = ir.discovery
    local_name = discovery.local_name if discovery.type == DiscoveryType.BLUETOOTH else None
    names: dict[str, str] = ir.extra.get("ble_service_names", {})
    service_uuids = [
        u
        for u in ir.extra.get("ble_service_uuids", [])
        if not u.lower().endswith(_SIG) and not _SKIP.search(names.get(u, ""))
    ]
    platforms = [
        p
        for p, items in (
            ("binary_sensor", binary_sensors),
            ("fan", fans),
            ("sensor", sensors),
            ("switch", switches),
        )
        if items
    ]
    return {
        "fans": fans,
        "switches": switches,
        "sensors": sensors,
        "binary_sensors": binary_sensors,
        "state": entities,
        "device_info": device_info,
        "local_name": local_name,
        # Advertised vendor services, for matching when the app filters by name only.
        "service_uuids": service_uuids,
        "platforms": platforms,
        "unmapped": unmapped,
        "domain": domain,
    }
