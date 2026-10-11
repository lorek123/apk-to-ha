# SPDX-License-Identifier: MIT
"""Fixtures for JBL Portable runtime tests: a fake device speaking the frame protocol."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from bleak.exc import BleakError
from jbllink_sdk import client as sdk_client
from jbllink_sdk import protocol

ADDRESS = "AA:BB:CC:DD:EE:FF"
ADVERT_NAME = "JBL Portable 1234"
DEVICE_NAME = "Test device"
MANUFACTURER_DATA = {protocol.MANUFACTURER_IDS[0]: b"\x00\x00"}
PRODUCT_ID = "1ebc"
CLASSIC_PRODUCT_ID = "0023"
# Version reply bytes, and the string the app shows for them.
VERSION_BYTES = bytes([0x01, 0x10, 0x05])
VERSION = "1.10.5"
# What the device reports at start: one value per setting the integration shows.
VALUES: dict[str, int] = {
    "feedback_tone_status": 1,
    "hfp_status": 1,
    "eq_mode": 0,
    "mfb_status": 0,
}
BATTERY = 0x50  # level in bits 0-6, bit 7 = charging


class FakeDevice:
    """Answers request frames from `values`, acknowledges settings, records every write."""

    def __init__(self) -> None:
        self.values: dict[str, int] = dict(VALUES)
        self.battery = BATTERY
        self.product_id = PRODUCT_ID
        self.writes: list[bytes] = []
        self.ack_status = protocol.ACK_OK
        self.reachable = True
        self.is_connected = False
        self.services = SimpleNamespace(
            get_characteristic=lambda uuid: object() if uuid == protocol.WRITE_UUID else None
        )
        self._notify: Callable[[Any, bytearray], None] | None = None

    def settings_written(self) -> list[tuple[int, int]]:
        """(opcode, value) of every setting written, in order."""
        opcodes = {s.opcode for s in protocol.SETTINGS.values()}
        return [(op, p[0]) for op, p in map(_frame, self.writes) if op in opcodes]

    async def start_notify(self, uuid: str, callback: Callable[[Any, bytearray], None]) -> None:
        assert uuid == protocol.NOTIFY_UUID
        self._notify = callback

    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = False) -> None:
        assert uuid == protocol.WRITE_UUID
        self.writes.append(bytes(data))
        for reply in self._answer(*_frame(bytes(data))):
            assert self._notify is not None
            self._notify(None, bytearray(reply))

    async def disconnect(self) -> None:
        self.is_connected = False
        self._notify = None

    def _tokens(self, ids: list[int]) -> bytes:
        out = bytearray([0])  # this device (index 0)
        for token in ids:
            name, size, encoding = protocol.TOKENS[token]
            if encoding == "level_charging_bit7":
                value = bytes([self.battery])
            elif encoding == "utf8":
                value = DEVICE_NAME.encode()
            elif name == "product_id" and size:
                value = bytes.fromhex(self.product_id).rjust(size, b"\x00")
            else:
                value = bytes(range(1, (size or 1) + 1))
            out += bytes([token]) + (bytes([len(value)]) if size is None else b"") + value
        return bytes(out)

    def _answer(self, opcode: int, payload: bytes) -> list[bytes]:
        setting = next((s for s in protocol.SETTINGS.values() if s.opcode == opcode), None)
        if setting is not None:
            if self.ack_status == protocol.ACK_OK:
                self.values[setting.field] = payload[0]
            ack = protocol.ACK_OPCODE[opcode]
            return [protocol.encode(ack, bytes([opcode, self.ack_status]))]
        requests = [r for r in (protocol.INFO, protocol.VERSION, *protocol.POLL) if r]
        req = next((r for r in requests if (r.opcode, r.payload) == (opcode, payload)), None)
        if req is None:
            return []
        reply = req.replies[0]
        kind, field = protocol.REPLIES[reply]
        if kind == "tokens":
            asked = [b for b in payload if b in protocol.TOKENS] or list(protocol.TOKENS)
            return [protocol.encode(reply, self._tokens(asked))]
        if kind == "version":
            return [protocol.encode(reply, VERSION_BYTES)]
        if field in self.values:
            return [protocol.encode(reply, bytes([self.values[field]]))]
        return []  # a model without this feature stays silent


def _frame(data: bytes) -> tuple[int, bytes]:
    return next(protocol.frames(data))


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Make custom_components/ loadable in every test."""


@pytest.fixture(autouse=True)
def auto_enable_bluetooth(enable_bluetooth: None) -> None:
    """bluetooth_adapters is a manifest dependency; phcc mocks the adapters."""


@pytest.fixture(autouse=True)
def fast_replies() -> Iterator[None]:
    """A silent device costs one reply timeout per request: keep it short."""
    with patch.object(protocol, "REPLY_TIMEOUT", 0.05):
        yield


@pytest.fixture
def device() -> Iterator[FakeDevice]:
    fake = FakeDevice()
    ble_device = SimpleNamespace(address=ADDRESS, name=ADVERT_NAME)
    info = SimpleNamespace(
        address=ADDRESS,
        name=ADVERT_NAME,
        manufacturer_data=MANUFACTURER_DATA,
        service_uuids=[],
        device=ble_device,
    )

    async def connect(*args: Any, **kwargs: Any) -> FakeDevice:
        if not fake.reachable:
            raise BleakError("out of range")
        fake.is_connected = True
        return fake

    with (
        patch.object(sdk_client, "establish_connection", connect),
        patch(
            "homeassistant.components.bluetooth.async_ble_device_from_address",
            return_value=ble_device,
        ),
        patch(
            "homeassistant.components.bluetooth.async_discovered_service_info",
            return_value=[info],
        ),
        patch("homeassistant.components.bluetooth.async_address_present", return_value=True),
    ):
        yield fake
