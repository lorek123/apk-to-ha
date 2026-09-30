# SPDX-License-Identifier: MIT
"""BLE client for BlueGate: one authenticated action per connection (like the app)."""
from __future__ import annotations

import asyncio
import logging

from bleak.backends.device import BLEDevice
from bleak.exc import BleakError
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection

from . import auth

_LOGGER = logging.getLogger(__name__)

SERVICE_UUIDS = ["6a7e6a7e-4929-42d0-0000-fcc5a35e13f1"]
CHALLENGE_UUID = "00000100-0000-1000-8000-00805f9b34fb"
CLIENT_KEY_UUID = "00000102-0000-1000-8000-00805f9b34fb"
CLIENT_NONCE_UUID = "00000103-0000-1000-8000-00805f9b34fb"
PROOF_UUID = "00000101-0000-1000-8000-00805f9b34fb"
ACK_UUID = "00000105-0000-1000-8000-00805f9b34fb"
ACTION_UUID = "00000106-0000-1000-8000-00805f9b34fb"

PRIMARY_ACTION = 1
# Authenticates and checks permissions without actuating anything.
PROBE_ACTION = 128
# The app sends this action by not writing ACTION_UUID at all.
IMPLICIT_ACTION = 1

ACTION_TIMEOUT = 30.0


class BluegateConnectionError(Exception):
    """The device couldn't be reached or broke off the exchange."""


class BluegateAuthError(BluegateConnectionError):
    """The device rejected our key: not enrolled yet, or revoked."""


class BluegateClient:
    """Runs authenticated actions on one device with one key."""

    def __init__(self, ble_device: BLEDevice, private_key_pem: str) -> None:
        self._device = ble_device
        self._key = auth.load_private_key(private_key_pem)  # fails fast on a bad key
        self._lock = asyncio.Lock()

    @property
    def address(self) -> str:
        return self._device.address

    def set_ble_device(self, ble_device: BLEDevice) -> None:
        """Use the freshest BLEDevice (the best adapter/path) from advertisements."""
        self._device = ble_device

    async def perform(self, action: int) -> None:
        """Authenticate and run *action*; raises AuthError if the key isn't accepted."""
        async with self._lock, asyncio.timeout(ACTION_TIMEOUT):
            await self._run(action)

    async def verify_enrolled(self) -> None:
        """Check the key is accepted, without actuating anything."""
        await self.perform(PROBE_ACTION)

    async def _run(self, action: int) -> None:
        try:
            client = await establish_connection(
                BleakClientWithServiceCache, self._device, self._device.name or self.address
            )
        except (BleakError, TimeoutError) as exc:
            raise BluegateConnectionError(f"Cannot connect to {self.address}") from exc
        try:
            if action != IMPLICIT_ACTION:
                await client.write_gatt_char(ACTION_UUID, bytes([action]), response=True)
            challenge = bytes(await client.read_gatt_char(CHALLENGE_UUID))
            await client.write_gatt_char(
                CLIENT_KEY_UUID, auth.public_key_bytes(self._key), response=True
            )
            client_nonce = auth.new_client_nonce()
            await client.write_gatt_char(CLIENT_NONCE_UUID, client_nonce, response=True)
            message = auth.signed_message(challenge, client_nonce)
            await client.write_gatt_char(PROOF_UUID, auth.sign(self._key, message), response=True)
            ack = bytes(await client.read_gatt_char(ACK_UUID))
        except BleakError as exc:
            raise BluegateConnectionError(f"Exchange with {self.address} failed") from exc
        except auth.AuthProtocolError as exc:
            raise BluegateConnectionError(str(exc)) from exc
        finally:
            await client.disconnect()
        if not ack or ack[0] != 1:
            raise BluegateAuthError(f"{self.address} did not accept our key")
