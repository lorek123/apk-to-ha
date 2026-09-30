# SPDX-License-Identifier: MIT
"""Fixtures for Firepit runtime tests: a fake device holding GATT values."""
from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from bleak.exc import BleakError
from firepit_sdk import client as sdk_client

ADDRESS = "AA:BB:CC:DD:EE:FF"
NAME = "FirePit 1234"
# What the fake device holds at start: every characteristic Home Assistant reads.
INITIAL: dict[str, bytes] = {
    sdk_client.FAN_SPEED_UUID: bytes.fromhex("02"),
    sdk_client.USB_CHARGE_OUT_UUID: bytes.fromhex("01"),
    sdk_client.BATTERY_LEVEL_UUID: bytes.fromhex("50"),
    sdk_client.LED_STATUS_UUID: bytes.fromhex("07"),
    sdk_client.BATTERY_CURRENT_UUID: bytes.fromhex("2c01"),
    sdk_client.TEMPERATURE_UUID: bytes.fromhex("07"),
    sdk_client.USB_OUTPUT_CONTROL_UUID: bytes.fromhex("01"),
    sdk_client.MANUFACTURER_UUID: b"Test",
    sdk_client.MODEL_UUID: b"Test",
}


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Make custom_components/ loadable in every test."""


@pytest.fixture(autouse=True)
def auto_enable_bluetooth(enable_bluetooth: None) -> None:
    """bluetooth_adapters is a manifest dependency; phcc mocks the adapters."""


class FakeDevice:
    """Serves reads from `values` and records every write, like the real GATT server."""

    def __init__(self) -> None:
        self.values: dict[str, bytes] = dict(INITIAL)
        self.writes: list[tuple[str, bytes]] = []
        self.reachable = True
        self.is_connected = False

    async def read_gatt_char(self, uuid: str) -> bytearray:
        if uuid not in self.values:
            raise BleakError(f"characteristic {uuid} not found")
        return bytearray(self.values[uuid])

    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = False) -> None:
        self.writes.append((uuid, bytes(data)))
        self.values[uuid] = bytes(data)

    async def disconnect(self) -> None:
        self.is_connected = False


@pytest.fixture
def device() -> Iterator[FakeDevice]:
    fake = FakeDevice()
    ble_device = SimpleNamespace(address=ADDRESS, name=NAME)
    info = SimpleNamespace(
        address=ADDRESS, name=NAME, service_uuids=list(sdk_client.SERVICE_UUIDS), device=ble_device
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
