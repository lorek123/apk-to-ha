# SPDX-License-Identifier: MIT
"""Challenge-response authentication for BlueGate.

Protocol (derived from the vendor app):
  1. read the device challenge (nonce)
  2. write our public key (compressed SEC1 point)
  3. write 32 fresh random bytes (client nonce)
  4. write an ECDSA-SECP256R1-SHA256 signature over challenge ‖ client_nonce
     (raw r‖s)
  5. read the acknowledgement: first byte 1 means accepted

Key handling:
  - One key pair per device, generated from the OS CSPRNG by `cryptography`.
  - The private key leaves this module only as PKCS#8 PEM for the caller to store
    (Home Assistant keeps it in the config entry). It is never logged, printed,
    or included in exception messages.
  - Only the public key (and a short fingerprint) is ever shown to the user.
"""
from __future__ import annotations

import hashlib
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

CURVE = ec.SECP256R1()
_COORD_BYTES = 32
CLIENT_NONCE_LENGTH = 32
# We only sign device challenges of a sane size: an unexpected length means a
# protocol error (or something that isn't the device), not data to sign.
CHALLENGE_MIN_LENGTH = 8
CHALLENGE_MAX_LENGTH = 64


class AuthProtocolError(ValueError):
    """The device's challenge or key material doesn't match the protocol."""


def generate_private_key() -> str:
    """A new private key as unencrypted PKCS#8 PEM (for secure storage by the caller)."""
    key = ec.generate_private_key(CURVE)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def load_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    """Parse a stored key, refusing anything but an EC key on the protocol's curve."""
    try:
        key = serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise AuthProtocolError("stored private key is unreadable") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != CURVE.name:
        raise AuthProtocolError("stored private key is not an EC key on the expected curve")
    return key


def public_key_bytes(key: ec.EllipticCurvePrivateKey) -> bytes:
    """The public key as the device expects it."""
    return key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )


def public_key_hex(pem: str) -> str:
    """Public key in hex, for the user to enrol on the device."""
    return public_key_bytes(load_private_key(pem)).hex()


def fingerprint(pem: str) -> str:
    """Short, human-comparable fingerprint of the public key (SHA-256, 8 bytes)."""
    digest = hashlib.sha256(public_key_bytes(load_private_key(pem))).hexdigest()[:16]
    return ":".join(digest[i : i + 4] for i in range(0, 16, 4))


def new_client_nonce() -> bytes:
    """Fresh random bytes for one authentication (never reused)."""
    return secrets.token_bytes(CLIENT_NONCE_LENGTH)


def signed_message(challenge: bytes, client_nonce: bytes) -> bytes:
    """The exact bytes the device verifies."""
    if not CHALLENGE_MIN_LENGTH <= len(challenge) <= CHALLENGE_MAX_LENGTH:
        raise AuthProtocolError(f"unexpected challenge length {len(challenge)}")
    if len(client_nonce) != CLIENT_NONCE_LENGTH:
        raise AuthProtocolError("client nonce has the wrong length")
    return b"".join([challenge, client_nonce])


def sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """ECDSA-SHA256 signature as raw r‖s."""
    der = key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(_COORD_BYTES, "big") + s.to_bytes(_COORD_BYTES, "big")
