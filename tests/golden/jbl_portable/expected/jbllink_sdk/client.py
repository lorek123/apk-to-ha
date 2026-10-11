# SPDX-License-Identifier: MIT
"""BLE client for JBL Portable: the command protocol over the device's GATT pair.

Each operation connects, subscribes to the notify characteristic, exchanges
frames (see protocol.py) and disconnects again.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager

from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from . import protocol
from .protocol import Session, Value

_LOGGER = logging.getLogger(__name__)

OPERATION_TIMEOUT = 30.0


class JbllinkConnectionError(Exception):
    """The device couldn't be reached or broke off the exchange."""


class JbllinkUnsupportedError(Exception):
    """The device doesn't have the JBL Portable command characteristics."""


def matches(manufacturer_data: Mapping[int, bytes]) -> bool:
    """Whether an advertisement carries the manufacturer data the app scans for."""
    return any(m in manufacturer_data for m in protocol.MANUFACTURER_IDS)


class JbllinkClient:
    """One JBL Portable device; safe to share, operations are serialised."""

    def __init__(self, ble_device: BLEDevice) -> None:
        self._device = ble_device
        self._lock = asyncio.Lock()

    @property
    def address(self) -> str:
        return self._device.address

    def set_ble_device(self, ble_device: BLEDevice) -> None:
        """Use the freshest BLEDevice (the best adapter/path) from advertisements."""
        self._device = ble_device

    async def read_device_info(self) -> dict[str, Value]:
        """Name, product id, firmware version, ... as far as the device answers."""
        async with self._session() as session:
            return await session.read_device_info()

    async def read_state(self) -> dict[str, Value]:
        """Every state value the device answers for (models answer subsets)."""
        async with self._session() as session:
            return await session.read_state()

    async def apply(self, key: str, value: int) -> None:
        """Change a setting; returns once the device has acknowledged it."""
        async with self._session() as session:
            try:
                await session.apply(key, value)
            except protocol.ProtocolError as exc:
                raise JbllinkConnectionError(str(exc)) from exc

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[Session]:
        """Lock, connect (with retries), subscribe, always disconnect; a timeout bounds it all."""
        async with self._lock:
            try:
                async with asyncio.timeout(OPERATION_TIMEOUT):
                    device = self._device
                    client = await establish_connection(
                        BleakClientWithServiceCache, device, device.name or device.address
                    )
                    try:
                        if client.services.get_characteristic(protocol.WRITE_UUID) is None:
                            raise JbllinkUnsupportedError(
                                f"{self.address} has no {protocol.WRITE_UUID}"
                            )

                        async def write(data: bytes) -> None:
                            # With response: the app's write type on Bluetooth LE links.
                            await client.write_gatt_char(protocol.WRITE_UUID, data, response=True)

                        session = Session(write)
                        await client.start_notify(
                            protocol.NOTIFY_UUID, lambda _, data: session.feed(bytes(data))
                        )
                        yield session
                    finally:
                        await client.disconnect()
            except (BleakError, TimeoutError) as exc:
                raise JbllinkConnectionError(f"{self.address}: {exc!r}") from exc
