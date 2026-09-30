# SPDX-License-Identifier: MIT
"""Fixtures for BlueGate runtime tests: a fake device that really verifies signatures."""
from __future__ import annotations

import secrets
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from bleak.exc import BleakError
from bluegate_sdk import client as sdk_client
from bluegate_sdk.auth import CURVE
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ADDRESS = "AA:BB:CC:DD:EE:FF"
COORD = 32


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Make custom_components/ loadable in every test."""


@pytest.fixture(autouse=True)
def auto_enable_bluetooth(enable_bluetooth: None) -> None:
    """bluetooth_adapters is a manifest dependency; phcc mocks the adapters."""


class FakeDevice:
    """Speaks the extracted protocol and checks every signature like the real device."""

    def __init__(self) -> None:
        self.enrolled: set[bytes] = set()
        self.actions: list[int] = []  # actions actually carried out
        self.client_nonces: list[bytes] = []
        self.reachable = True
        self._session: dict[str, Any] = {}

    def new_session(self) -> None:
        self._session = {"action": sdk_client.IMPLICIT_ACTION, "challenge": secrets.token_bytes(32)}

    async def write_gatt_char(self, uuid: str, data: bytes, response: bool = False) -> None:
        s = self._session
        if uuid == sdk_client.ACTION_UUID:
            s["action"] = data[0]
        elif uuid == sdk_client.CLIENT_KEY_UUID:
            s["key"] = bytes(data)
        elif uuid == sdk_client.CLIENT_NONCE_UUID:
            s["client_nonce"] = bytes(data)
            self.client_nonces.append(bytes(data))
        elif uuid == sdk_client.PROOF_UUID:
            s["accepted"] = self._verify(bytes(data))
            if s["accepted"] and s["action"] != sdk_client.PROBE_ACTION:
                self.actions.append(s["action"])

    async def read_gatt_char(self, uuid: str) -> bytes:
        if uuid == sdk_client.CHALLENGE_UUID:
            return self._session["challenge"]
        if uuid == sdk_client.ACK_UUID:
            return b"\x01" if self._session.get("accepted") else b"\x00"
        raise BleakError(f"unexpected read {uuid}")

    async def disconnect(self) -> None:
        self._session = {}

    def _verify(self, sig: bytes) -> bool:
        s = self._session
        key = s.get("key")
        if key is None or key not in self.enrolled:
            return False
        roles = {"challenge": s["challenge"], "client_nonce": s.get("client_nonce", b"")}
        message = b"".join(roles[r] for r in ["challenge", "client_nonce"])
        if len(sig) != 2 * COORD:
            return False
        der = encode_dss_signature(int.from_bytes(sig[:COORD], "big"), int.from_bytes(sig[COORD:], "big"))
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(CURVE, key).verify(
                der, message, ec.ECDSA(hashes.SHA256())
            )
        except (InvalidSignature, ValueError):
            return False
        return True


@pytest.fixture
def device() -> Iterator[FakeDevice]:
    fake = FakeDevice()
    ble_device = SimpleNamespace(address=ADDRESS, name="BlueGate")
    info = SimpleNamespace(
        address=ADDRESS, name="BlueGate", service_uuids=list(sdk_client.SERVICE_UUIDS)
    )

    async def connect(*args: Any, **kwargs: Any) -> FakeDevice:
        if not fake.reachable:
            raise BleakError("out of range")
        fake.new_session()
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
