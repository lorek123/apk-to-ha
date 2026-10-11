# SPDX-License-Identifier: MIT
"""JBL Portable command protocol: request frames out, reply frames back.

Every request is one frame written to the device's write characteristic; the
device answers with frames on its notify characteristic. The frame layout, the
opcodes, the reply decoders and the model table come from the JBL Portable app.

This module has no Bluetooth code: a `Session` is given a coroutine that writes
bytes and is fed the notifications, so the same protocol runs over any link.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass

SERVICE_UUID: str | None = "65786365-6c70-6f69-6e74-2e636f6d0000"
NOTIFY_UUID = "65786365-6c70-6f69-6e74-2e636f6d0001"
WRITE_UUID = "65786365-6c70-6f69-6e74-2e636f6d0002"
# Bluetooth SIG company IDs whose manufacturer data the app's scan accepts.
MANUFACTURER_IDS: tuple[int, ...] = (3787, 87, )

SYNC = bytes([170])
HEADER_LEN = 3  # sync, opcode, length
OPCODE_AT = 1
LENGTH_AT = 2
REPLY_TIMEOUT = 2.0  # the app's command timeout


@dataclass(frozen=True)
class Request:
    name: str
    opcode: int
    payload: bytes
    replies: tuple[int, ...]


# Device information (once per connection setup) and the state read on every poll.
INFO = Request("GetDevInfo", 0x11, bytes.fromhex(""), (0x12, ))
VERSION = Request("ReqVer", 0x41, bytes.fromhex(""), (0x42, ))
POLL: tuple[Request, ...] = (
    Request("ReqBattery", 0x13, bytes.fromhex("0044"), (0x12, )),
    Request("ReqEQMode", 0x61, bytes.fromhex(""), (0x62, )),
    Request("ReqFeedbackTone", 0x65, bytes.fromhex(""), (0x66, )),
    Request("ReqHFP", 0x68, bytes.fromhex(""), (0x69, )),
    Request("ReqMFB", 0x33, bytes.fromhex(""), (0x34, )),
)


@dataclass(frozen=True)
class Setting:
    """A value the app writes, acknowledged by [opcode, status] in an ack frame."""

    opcode: int
    field: str  # the state field it changes (read back by `read`)
    values: tuple[int, ...]
    read: str


ACK_OPCODE: dict[int, int] = {
    0x67: 0x00,
    0x70: 0x00,
    0x63: 0x00,
    0x32: 0x00,
}
ACK_OK = 0  # the status the app treats as success
SETTINGS: dict[str, Setting] = {
    "feedback_tone": Setting(0x67, "feedback_tone_status", (0, 1), "ReqFeedbackTone"),
    "hfp": Setting(0x70, "hfp_status", (0, 1), "ReqHFP"),
    "eq_mode": Setting(0x63, "eq_mode", (0, 1, ), "ReqEQMode"),
    "mfb": Setting(0x32, "mfb_status", (0, 1, ), "ReqMFB"),
}

# Reply opcode → how its payload decodes.
REPLIES: dict[int, tuple[str, str | None]] = {
    0x12: ("tokens", None),
    0x34: ("uint8", "mfb_status"),
    0x42: ("version", "firmware_version"),
    0x62: ("uint8", "eq_mode"),
    0x64: ("uint8", "eq_mode"),
    0x66: ("uint8", "feedback_tone_status"),
    0x69: ("uint8", "hfp_status"),
    0x72: ("uint8", "light_status"),
    0xb0: ("uint8", "sq_status"),
    0xb3: ("uint8", "playtime_boost_status"),
}
# Device-info token id → (field, size or None if length-prefixed, encoding).
TOKENS: dict[int, tuple[str, int | None, str]] = {
    0x42: ("product_id", 2, "hex"),
    0x43: ("model_id", 1, "hex"),
    0x44: ("battery_status", 1, "level_charging_bit7"),
    0x45: ("linked_device_count", 1, "hex"),
    0x46: ("active_channel", 1, "hex"),
    0x47: ("audio_source", 1, "hex"),
    0x48: ("mac_address", 6, "hex"),
    0xc1: ("device_name", None, "utf8"),
}

# Product id → (model name, reachable over Bluetooth LE). From the app's model
# table; False means the app talks to that model over classic Bluetooth, which
# Home Assistant's Bluetooth stack can't open.
MODELS: dict[str, tuple[str, bool | None]] = {
    "0023": ("JBL Flip 3", False),
    "0024": ("JBL Xtreme", False),
    "1ebc": ("JBL Charge 3", True),
    "1ed1": ("JBL Flip 4", True),
    "1ed2": ("pulse3", True),
    "1ee7": ("JBL Boombox", True),
    "1efc": ("JBL Xtreme 2", True),
    "1f17": ("JBL Charge 4", True),
    "1f26": ("JBL Xtreme 2(QCC)", True),
    "1f27": ("JBL BoomBox(QCC)", True),
    "1f29": ("JBL Charge 4(QCC)", True),
    "1f31": ("JBL Flip 5", True),
    "1f53": ("JBL Boombox 2", False),
    "1f56": ("pulse4", True),
    "202f": ("JBL Xtreme 3 ", True),
    "2038": ("JBL Xtreme 2(GM)", True),
    "2040": ("JBL Charge 5", True),
    "204f": ("JBL Flip 6", False),
    "2050": ("JBL Pulse 5", False),
    "206d": ("JBL Boombox 3", False),
    "2075": ("JBL Boombox 3 Wi-Fi", True),
    "208c": ("JBL Charge 5 Wi-Fi", True),
    "20dc": ("JBL Xtreme 4 ", True),
    "20e3": ("JBL Charge 6", True),
    "20e4": ("JBL GO 4", True),
    "20f5": ("JBL CLIP 5", True),
    "2107": ("JBL Flip 7", True),
    "210a": ("JBL GO 4", True),
    "2132": ("JBL Grip", True),
    "214c": ("JBL Tuner 3", True),
    "214e": ("JBL Boombox 4", True),
    "215c": ("JBL Go 4 DUO", True),
    "2168": ("JBL GO 5", True),
    "2169": ("JBL Xtreme 5", True),
    "2181": ("JBLGo4DUOR", True),
    "2185": ("JBL Flip Essential 3 SE", True),
    "218a": ("JBL Charge Essential 3 SE", True),
    "218b": ("JBL Pulse 6", True),
    "21a2": ("JBL CLIP 6", True),
}

type Value = int | bool | str


class ProtocolError(Exception):
    """The device answered, but not as the protocol says it should."""


class RejectedError(ProtocolError):
    """The device acknowledged a setting with a failure status."""


def encode(opcode: int, payload: bytes = b"") -> bytes:
    header = bytearray(SYNC)
    header.insert(OPCODE_AT, opcode & 0xFF)
    header.insert(LENGTH_AT, len(payload) & 0xFF)
    return bytes(header) + payload


def frames(data: bytes) -> Iterator[tuple[int, bytes]]:
    """(opcode, payload) for each frame in one notification."""
    i = 0
    while i + HEADER_LEN <= len(data):
        if SYNC and data[i : i + len(SYNC)] != SYNC:
            i += 1  # resynchronise on the next sync byte
            continue
        head = data[i : i + HEADER_LEN]
        length = head[LENGTH_AT]
        yield head[OPCODE_AT], data[i + HEADER_LEN : i + HEADER_LEN + length]
        i += HEADER_LEN + length


def _version_part(b: int) -> str:
    # The app prints each byte's hex digits as a decimal number (0x10 → "10").
    text = f"{b:02x}"
    return str(int(text)) if text.isdigit() else str(b)


def decode_tokens(payload: bytes) -> dict[str, Value]:
    """Device-info reply: the speaker's index (0 = this one), then token/value pairs."""
    if not payload:
        return {}
    out: dict[str, Value] = {"device_index": payload[0]}
    i = 1
    while i < len(payload):
        spec = TOKENS.get(payload[i])
        if spec is None:
            break  # an unknown token: its length is unknown too
        name, size, encoding = spec
        i += 1
        if size is None:
            if i >= len(payload):
                break
            size, i = payload[i], i + 1
        value = payload[i : i + size]
        i += size
        if len(value) < size:
            break
        if encoding == "level_charging_bit7":
            out[name] = min(value[0] & 0x7F, 100)
            out[f"{name}_charging"] = bool(value[0] & 0x80)
        elif encoding == "utf8":
            out[name] = value.decode("utf-8", "replace")
        elif encoding == "uint":
            out[name] = int.from_bytes(value, "big")
        else:
            out[name] = value.hex()
    return out


def decode(opcode: int, payload: bytes) -> dict[str, Value]:
    """State fields carried by one reply frame ({} for one this module doesn't know)."""
    kind, field = REPLIES.get(opcode, ("", None))
    if kind == "uint8" and payload and field:
        return {field: payload[0]}
    if kind == "version" and field:
        return {field: ".".join(_version_part(b) for b in payload)}
    if kind == "tokens":
        return decode_tokens(payload)
    return {}


def model(product_id: str | None) -> tuple[str | None, bool | None]:
    """(model name, reachable over Bluetooth LE) for a product id, if the app knows it."""
    if not product_id:
        return None, None
    return MODELS.get(product_id.lower(), (None, None))


class Session:
    """Requests over one connection. Feed it every notification; one request at a time."""

    def __init__(self, write: Callable[[bytes], Awaitable[None]]) -> None:
        self._write = write
        self._inbox: asyncio.Queue[tuple[int, bytes]] = asyncio.Queue()
        self._lock = asyncio.Lock()

    def feed(self, data: bytes) -> None:
        for frame in frames(bytes(data)):
            self._inbox.put_nowait(frame)

    async def _exchange(
        self, opcode: int, payload: bytes, accept: Callable[[int, bytes], bool]
    ) -> tuple[int, bytes] | None:
        """Write one frame; the first reply frame *accept*s, None on timeout."""
        async with self._lock:
            while not self._inbox.empty():
                self._inbox.get_nowait()  # replies to an earlier, abandoned request
            await self._write(encode(opcode, payload))
            try:
                async with asyncio.timeout(REPLY_TIMEOUT):
                    while True:
                        op, data = await self._inbox.get()
                        if accept(op, data):
                            return op, data
            except TimeoutError:
                return None

    async def request(self, req: Request) -> dict[str, Value]:
        """The fields the answer carries; {} if the device didn't answer (not on this model)."""

        def accept(op: int, data: bytes) -> bool:
            # Token replies name the speaker they describe: take this one's (index 0).
            return op in req.replies and decode(op, data).get("device_index", 0) == 0

        reply = await self._exchange(req.opcode, req.payload, accept)
        if reply is None:
            return {}
        fields = decode(*reply)
        fields.pop("device_index", None)
        return fields

    async def read_state(self) -> dict[str, Value]:
        state: dict[str, Value] = {}
        for req in POLL:
            state.update(await self.request(req))
        return state

    async def read_device_info(self) -> dict[str, Value]:
        info: dict[str, Value] = {}
        for req in (INFO, VERSION):
            if req is not None:
                info.update(await self.request(req))
        return info

    async def apply(self, key: str, value: int) -> None:
        """Write a setting and wait for the device to acknowledge it."""
        setting = SETTINGS[key]
        if value not in setting.values:
            raise ValueError(f"{key}: {value} not one of {setting.values}")
        ack = ACK_OPCODE[setting.opcode]

        def accept(op: int, data: bytes) -> bool:
            return op == ack and len(data) >= 2 and data[0] == setting.opcode

        reply = await self._exchange(setting.opcode, bytes([value]), accept)
        if reply is None:
            raise ProtocolError(f"{key}: no acknowledgement")
        status = reply[1][1]
        if status != ACK_OK:
            raise RejectedError(f"{key}: refused (status {status})")

