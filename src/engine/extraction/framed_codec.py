# SPDX-License-Identifier: MIT
"""P2-8c — Reference codec for framed command protocols (``extra["framed"]``).

The framed scanner describes a protocol as data (frame layout, commands, reply
decoders, device-info tokens); this module turns that description into bytes
and back. It is what the hardware check (scripts/framed_hw_check.py) drives a
real device with, and what the generated SDK's codec must agree with.

    frame   [{"kind": "const", "value": 0xAA}, {"kind": "opcode"},
             {"kind": "length"}, {"kind": "payload"}]
    reply   {"opcode": 0x62, "decode": "uint8", "field": "eq_mode"}
            {"opcode": 0x42, "decode": "version", "field": "firmware_version"}
            {"opcode": 0x12, "decode": "tokens"}  (device-info token list)
    token   {"id": 0x44, "name": "battery_status", "size": 1,
             "encoding": "level_charging_bit7"}   (size None: length-prefixed)
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def encode(frame: list[dict[str, Any]], opcode: int, payload: bytes = b"") -> bytes:
    """One request frame."""
    out = bytearray()
    for part in frame:
        match part["kind"]:
            case "const":
                out.append(part["value"] & 0xFF)
            case "opcode":
                out.append(opcode & 0xFF)
            case "length":
                out.append(len(payload) & 0xFF)
            case "payload":
                out += payload
    return bytes(out)


def command_payload(command: dict[str, Any], args: dict[str, int] | None = None) -> bytes:
    """A command's payload bytes, its parameters taken from *args* (or their defaults)."""
    args = args or {}
    out = bytearray()
    for item in command["payload"]:
        if "value" in item:
            out.append(item["value"] & 0xFF)
        elif "param" in item:
            value = args.get(item["param"], item.get("default"))
            if value is None:
                raise ValueError(f"{command['name']}: no value for {item['param']}")
            out.append(int(value) & 0xFF)
        else:
            raise ValueError(f"{command['name']}: payload item not understood: {item}")
    return bytes(out)


def frames(frame: list[dict[str, Any]], data: bytes) -> Iterator[tuple[int, bytes]]:
    """(opcode, payload) for each frame in *data* (one notification may hold several)."""
    sync = bytes(p["value"] for p in frame if p["kind"] == "const")
    kinds = [p["kind"] for p in frame]
    header = len(kinds) - 1  # every part but the payload is one byte
    i = 0
    while i + header <= len(data):
        if sync and data[i : i + len(sync)] != sync:
            i += 1  # resynchronise on the next sync byte
            continue
        head = data[i : i + header]
        opcode = head[kinds.index("opcode")]
        length = head[kinds.index("length")]
        payload = data[i + header : i + header + length]
        yield opcode, payload
        i += header + length


def decode_reply(
    reply: dict[str, Any], payload: bytes, tokens: dict[int, dict[str, Any]]
) -> dict[str, Any]:
    """State fields carried by one reply."""
    match reply["decode"]:
        case "uint8":
            return {reply["field"]: payload[0]} if payload else {}
        case "version":
            return {reply["field"]: ".".join(_version_part(b) for b in payload)}
        case "tokens":
            return decode_tokens(payload, tokens)
    return {}


def _version_part(b: int) -> str:
    # The app prints each byte's hex digits as a decimal number ("10" → 10).
    text = f"{b:02x}"
    return str(int(text)) if text.isdigit() else str(b)


def decode_tokens(payload: bytes, tokens: dict[int, dict[str, Any]]) -> dict[str, Any]:
    """Device-info reply: a device index, then token/value pairs.

    The index says which speaker the values belong to (a stereo pair answers for
    both); it is returned as ``device_index`` for the caller to filter on.
    """
    if not payload:
        return {}
    out: dict[str, Any] = {"device_index": payload[0]}
    i = 1
    while i < len(payload):
        spec = tokens.get(payload[i])
        if spec is None:
            break  # unknown token: its length is unknown too
        i += 1
        if spec["size"] is None:  # length-prefixed
            if i >= len(payload):
                break
            size, i = payload[i], i + 1
        else:
            size = spec["size"]
        value = payload[i : i + size]
        i += size
        if len(value) < size:
            break
        out.update(_token_value(spec, value))
    return out


def _token_value(spec: dict[str, Any], value: bytes) -> dict[str, Any]:
    name = spec["name"]
    match spec["encoding"]:
        case "level_charging_bit7":
            return {name: min(value[0] & 0x7F, 100), f"{name}_charging": bool(value[0] & 0x80)}
        case "utf8":
            return {name: value.decode("utf-8", errors="replace")}
        case "uint":
            return {name: int.from_bytes(value, "big")}
        case _:
            return {name: value.hex()}
