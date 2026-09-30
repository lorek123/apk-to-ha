# SPDX-License-Identifier: MIT
"""BLE client for Firepit: reads its state and writes its controls over GATT.

The characteristics, their encodings and the values written come from the
Firepit app. Each operation opens a connection and closes it again.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

_LOGGER = logging.getLogger(__name__)

# The app lists devices whose advertised name contains this.
LOCAL_NAME: str | None = "FirePit"
SERVICE_UUIDS: list[str] = ["ea4b0ed1-e88c-938c-4a47-2f15c2002ffd"]

FAN_SPEED_UUID = "b0631206-46bf-3186-e045-f2204b379011"
USB_CHARGE_OUT_UUID = "2ff4e772-d34f-5894-4f40-1addf9b6030b"
BATTERY_LEVEL_UUID = "00002a19-0000-1000-8000-00805f9b34fb"
LED_STATUS_UUID = "941e24c9-bc8a-c781-1a46-1cf77ae4a31e"
BATTERY_CURRENT_UUID = "1173bff9-0e3a-9887-3549-810ddff0eab2"
TEMPERATURE_UUID = "20c5de4b-8013-f0ab-fc4e-55b8b83875aa"
USB_OUTPUT_CONTROL_UUID = "6b2951c8-d59a-8cb3-e740-c36047217ff7"
MANUFACTURER_UUID = "00002a29-0000-1000-8000-00805f9b34fb"
MODEL_UUID = "00002a24-0000-1000-8000-00805f9b34fb"

# State key → (characteristic, encoding), all read on every refresh.
STATE: dict[str, tuple[str, str]] = {
    "fan_speed": (FAN_SPEED_UUID, "int8"),
    "usb_charge_out": (USB_CHARGE_OUT_UUID, "int8"),
    "battery_level": (BATTERY_LEVEL_UUID, "uint8"),
    "led_status": (LED_STATUS_UUID, "int8"),
    "battery_current": (BATTERY_CURRENT_UUID, "int16le"),
    "temperature": (TEMPERATURE_UUID, "int8"),
    "usb_output_control": (USB_OUTPUT_CONTROL_UUID, "bool"),
}
DEVICE_INFO: dict[str, str] = {
    "manufacturer": MANUFACTURER_UUID,
    "model": MODEL_UUID,
}
FAN_SPEED_LEVELS = 4  # 0 = off .. 4 = full

OPERATION_TIMEOUT = 30.0

type Value = int | bool | str


class FirepitConnectionError(Exception):
    """The device couldn't be reached or broke off the exchange."""


def matches(name: str | None, service_uuids: list[str]) -> bool:
    """Whether an advertisement is a Firepit (the app's own filter)."""
    if LOCAL_NAME and name and LOCAL_NAME in name:
        return True
    return any(uuid in service_uuids for uuid in SERVICE_UUIDS)


def decode(encoding: str, data: bytes) -> Value:
    """A characteristic value, decoded the way the app decodes it."""
    if encoding == "bool":
        return bool(data) and data[0] != 0
    if encoding == "utf8":
        return data.decode("utf-8", "replace").strip("\x00 ")
    signed = encoding.startswith("int")
    size = 2 if encoding.endswith("16le") else 1
    if len(data) < size:
        raise ValueError(f"{len(data)} bytes, expected {size}")
    return int.from_bytes(data[:size], "little", signed=signed)


class FirepitClient:
    """One Firepit; safe to share, operations are serialised."""

    def __init__(self, ble_device: BLEDevice) -> None:
        self._device = ble_device
        self._lock = asyncio.Lock()

    @property
    def address(self) -> str:
        return self._device.address

    def set_ble_device(self, ble_device: BLEDevice) -> None:
        """Use the freshest BLEDevice (the best adapter/path) from advertisements."""
        self._device = ble_device

    async def read_state(self) -> dict[str, Value | None]:
        """Every state value; None for one this firmware doesn't have or sent garbled."""
        async with self._connected() as client:
            state: dict[str, Value | None] = {}
            for key, (uuid, encoding) in STATE.items():
                state[key] = await self._read(client, uuid, encoding)
            return state

    async def read_device_info(self) -> dict[str, str]:
        """Device Information strings (manufacturer, model, ...) the device offers."""
        async with self._connected() as client:
            info: dict[str, str] = {}
            for field, uuid in DEVICE_INFO.items():
                value = await self._read(client, uuid, "utf8")
                if isinstance(value, str) and value:
                    info[field] = value
            return info

    async def set_fan_speed(self, level: int) -> None:
        """0 = off, 1..4 = speed (as the app's buttons send it)."""
        if not 0 <= level <= FAN_SPEED_LEVELS:
            raise ValueError(f"level {level} outside 0..4")
        await self._write(FAN_SPEED_UUID, bytes([level]))

    async def set_usb_charge_out(self, on: bool) -> None:
        await self._write(USB_CHARGE_OUT_UUID, bytes([1 if on else 0]))

    async def _write(self, uuid: str, data: bytes) -> None:
        async with self._connected() as client:
            try:
                await client.write_gatt_char(uuid, data, response=True)
            except BleakError as exc:
                raise FirepitConnectionError(f"Write to {uuid} failed: {exc}") from exc

    async def _read(
        self, client: BleakClientWithServiceCache, uuid: str, encoding: str
    ) -> Value | None:
        try:
            data = bytes(await client.read_gatt_char(uuid))
        except BleakError as exc:
            if not client.is_connected:
                raise FirepitConnectionError(f"Lost {self.address}") from exc
            _LOGGER.debug("%s: %s unavailable: %s", self.address, uuid, exc)
            return None
        try:
            return decode(encoding, data)
        except ValueError as exc:
            _LOGGER.debug("%s: %s undecodable: %s", self.address, uuid, exc)
            return None

    @asynccontextmanager
    async def _connected(self) -> AsyncIterator[BleakClientWithServiceCache]:
        """Lock, connect (with retries), always disconnect; a timeout bounds it all."""
        async with self._lock:
            try:
                async with asyncio.timeout(OPERATION_TIMEOUT):
                    device = self._device
                    client = await establish_connection(
                        BleakClientWithServiceCache, device, device.name or device.address
                    )
                    try:
                        yield client
                    finally:
                        await client.disconnect()
            except (BleakError, TimeoutError) as exc:
                raise FirepitConnectionError(f"{self.address}: {exc!r}") from exc
