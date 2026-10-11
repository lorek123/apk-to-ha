# SPDX-License-Identifier: MIT
"""P5 — Framed command protocols over GATT (``extra["framed"]``): entities.

The device has one write and one notify characteristic; state is read by sending
request frames and decoding the frames that answer them (see
extraction/framed_scanner.py). Entities come only from what the extraction
established:

  sensor         a device-info token the app decodes as a battery level
  binary_sensor  that token's charging bit
  switch         a setting the app sends 0/1 to from an on/off control, whose
                 value a request reads back, and whose acknowledgement is known
  select         the same, with values the app's UI names (indoor/outdoor)
  device info    the device-info reply (name, product id → model) and the
                 firmware version reply

Settings with values the app computes, or that it never names, are reported as
unmapped. Devices that answer only some requests (models implement subsets)
get entities only for what they answered at setup.

Models whose link the app opens over classic Bluetooth (PROTOCOL_GATT_BR_EDR,
SPP) are out of reach of Home Assistant's Bluetooth LE stack: the integration
recognises them by product id and refuses them with that reason.
"""

from __future__ import annotations

import re
from typing import Any

from ..extraction import framed_codec as codec
from ..ir.models import ProtocolIR

_ACRONYMS = {"eq", "hfp", "mfb", "led", "usb", "sq", "dsp"}
# Settings that aren't device features (pairing, analytics, links between speakers),
# matched as whole words of the command name (SetAppAck, not SetFeedbackTone).
_SKIP = {"dfu", "ota", "upgrade", "auth", "authentication", "analytics", "channel"}
_SKIP |= {"link", "aura", "auracast", "name", "ack"}
# Fake-device values the runtime tests start from, per entity kind.
_SAMPLE_BATTERY = 0x50  # 80 %, not charging


def _human(key: str) -> str:
    words = [w.upper() if w in _ACRONYMS else w for w in key.split("_")]
    text = " ".join(words)
    return text[0].upper() + text[1:]


def _ble_only(protocol: str | None) -> bool | None:
    """Whether a model's link is Bluetooth LE (None: the table doesn't say)."""
    if not protocol:
        return None
    p = protocol.upper()
    return bool(re.search(r"(?<![A-Z])(?:BLE|LE)(?![A-Z])", p)) and "BR_EDR" not in p


def build(ir: ProtocolIR, domain: str) -> dict[str, Any] | None:
    """Template context for a framed-protocol device, or None if one can't be built."""
    framed: dict[str, Any] | None = ir.extra.get("framed")
    if not framed:
        return None
    t = framed.get("transport", {})
    if not (t.get("write") and t.get("notify")):
        return None
    frame = framed["frame"]
    replies = {r["opcode"]: r for r in framed["replies"]}
    tokens = {t["id"]: t for t in framed["tokens"]}
    token_reply = next((op for op, r in replies.items() if r["decode"] == "tokens"), None)
    requests = [
        c
        for c in framed["commands"]
        if c["kind"] == "request"
        and c["complete"]
        and all("value" in i or "default" in i for i in c["payload"])
        and set(c["replies"]) & replies.keys()
    ]

    def request_ctx(c: dict[str, Any]) -> dict[str, Any]:
        payload = codec.command_payload(c)
        return {
            "name": c["name"],
            "opcode": c["opcode"],
            "payload": payload.hex(),
            "replies": [op for op in c["replies"] if op in replies],
            "frame": codec.encode(frame, c["opcode"], payload).hex(),
        }

    def reading(field: str) -> dict[str, Any] | None:
        """The request whose reply carries *field* (a uint8 reply)."""
        ops = {op for op, r in replies.items() if r.get("field") == field}
        return next((c for c in requests if not c["payload"] and set(c["replies"]) & ops), None)

    poll: dict[str, dict[str, Any]] = {}
    sensors: list[dict[str, Any]] = []
    binary_sensors: list[dict[str, Any]] = []
    switches: list[dict[str, Any]] = []
    selects: list[dict[str, Any]] = []
    unmapped: list[dict[str, str]] = []

    # Battery: a token the app decodes as level + charging bit, and the request for it.
    for tok in tokens.values():
        if tok["encoding"] != "level_charging_bit7" or token_reply is None:
            continue
        req = next(
            (
                c
                for c in requests
                if token_reply in c["replies"]
                and any(i.get("value") == tok["id"] for i in c["payload"])
            ),
            None,
        )
        if req is None:
            unmapped.append({"cmd": tok["name"], "reason": "no request reads this token alone"})
            continue
        poll[req["name"]] = request_ctx(req)
        sensors.append(
            {
                "key": "battery",
                "field": tok["name"],
                "device_class": "battery",
                "unit": "%",
                "state_class": "measurement",
                "sample": _SAMPLE_BATTERY & 0x7F,
            }
        )
        binary_sensors.append(
            {
                "key": "charging",
                "field": f"{tok['name']}_charging",
                "device_class": "battery_charging",
                "sample": bool(_SAMPLE_BATTERY & 0x80),
            }
        )
        break

    # Settings: set command + the request that reads the same field back.
    for c in framed["commands"]:
        words = {w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+", c["name"])}
        if c["kind"] != "set" or words & _SKIP:
            continue
        field = c.get("field")
        why = None
        if not field or len(c["params"]) != 1:
            why = "doesn't change one device field"
        elif not c.get("ack"):
            why = "acknowledgement not understood"
        elif not c.get("values_complete") or not c.get("values"):
            why = "values computed at run time, not all known"
        read = reading(field) if field else None
        if why is None and read is None:
            why = "no request reads it back"
        labels: dict[str, str] = c.get("value_labels") or {}
        values: list[int] = c.get("values") or []
        if why is None and set(labels) != {str(v) for v in values}:
            why = "the app doesn't name its values"
        if why is not None:
            unmapped.append({"cmd": c["name"], "reason": why})
            continue
        assert read is not None and field is not None
        key = re.sub(r"_(?:status|state|setting|mode_setting)$", "", field)
        entity: dict[str, Any] = {
            "key": key,
            "field": field,
            "set": c["name"],
            "set_opcode": c["opcode"],
            "ack_opcode": c["ack"]["opcode"],
            "ack_ok": c["ack"]["ok"],
            "read": read["name"],
        }
        poll[read["name"]] = request_ctx(read)
        if set(labels.values()) == {"on", "off"}:
            on = int(next(v for v, n in labels.items() if n == "on"))
            off = int(next(v for v, n in labels.items() if n == "off"))
            switches.append({**entity, "on": on, "off": off, "sample": on, "sample_state": "on"})
        else:
            options = {int(v): n for v, n in sorted(labels.items(), key=lambda i: int(i[0]))}
            first, *rest = options.items()
            selects.append(
                {
                    **entity,
                    "options": options,
                    "sample": first[0],
                    "sample_state": first[1],
                    "pick": rest[0] if rest else first,
                }
            )

    if not (sensors or switches or selects):
        return None

    info_req = next(
        (
            c
            for c in requests
            if token_reply in c["replies"] and not c["payload"] and token_reply is not None
        ),
        None,
    )
    version = next((op for op, r in replies.items() if r["decode"] == "version"), None)
    version_req = next((c for c in requests if version in c["replies"] and not c["payload"]), None)
    models = {
        pid.lower(): {"name": m.get("name") or pid, "ble": _ble_only(m.get("protocol"))}
        for pid, m in sorted(framed.get("models", {}).items())
    }
    platforms = [
        p
        for p, items in (
            ("binary_sensor", binary_sensors),
            ("select", selects),
            ("sensor", sensors),
            ("switch", switches),
        )
        if items
    ]
    entities = sensors + binary_sensors + switches + selects
    for e in entities:
        e["name"] = _human(e["key"])
    sync = [p["value"] for p in frame if p["kind"] == "const"]
    unsupported = sorted(m["name"] for m in models.values() if m["ble"] is False)
    return {
        "frame": frame,
        "sync": sync,
        "header_len": len(frame) - 1,
        "opcode_at": [p["kind"] for p in frame].index("opcode"),
        "length_at": [p["kind"] for p in frame].index("length"),
        "service": t.get("service"),
        "notify": t["notify"],
        "write": t["write"],
        "manufacturer_ids": framed.get("manufacturer_ids") or ir.discovery.manufacturer_ids,
        "replies": [replies[op] for op in sorted(replies)],
        "tokens": [tokens[i] for i in sorted(tokens)],
        "token_reply": token_reply,
        "info_request": request_ctx(info_req) if info_req else None,
        "version_request": request_ctx(version_req) if version_req else None,
        "poll": [poll[k] for k in sorted(poll)],
        "models": models,
        "unsupported_models": unsupported,
        "sensors": sensors,
        "binary_sensors": binary_sensors,
        "switches": switches,
        "selects": selects,
        "entities": entities,
        "platforms": platforms,
        "unmapped": unmapped,
        "domain": domain,
        "sample_battery": _SAMPLE_BATTERY,
    }
