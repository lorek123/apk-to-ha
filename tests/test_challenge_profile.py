# SPDX-License-Identifier: MIT
"""Tests for deriving a challenge-response profile from code (BlueGate-shaped)."""

# ruff: noqa: E501 — the Java fixtures reproduce decompiler output line for line
from __future__ import annotations

from pathlib import Path

from engine.extraction.challenge_profile import build
from engine.ir.models import (
    CryptoUsage,
    Direction,
    Endpoint,
    SigningComponent,
    SigningTrace,
    TransportType,
)

_KEYS = """package com.example.gate;
public final class KeyManager {
    public final byte[] compressPublicKeyPoint(byte[] p) {
        byte[] bArr = new byte[33];
        bArr[0] = (last & 1) == 1 ? (byte) 3 : (byte) 2;
        return bArr;
    }
    public final byte[] toRawSignature(byte[] derSig, int n) {
        if (derSig[0] != 48) { throw new IllegalArgumentException("Not a DER SEQUENCE"); }
        if (derSig[2] != 2) { throw new IllegalArgumentException("Expected INTEGER for r"); }
        return out;
    }
    private final KeyPair generate() {
        spec = new KeyGenParameterSpec.Builder(alias, 12).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1")).build();
    }
}
"""

_AUTH = """package com.example.gate;
public final class Authenticator {
    void start() {
        byte[] bArr = new byte[32];
        new SecureRandom().nextBytes(bArr);
        this.clientNonce = bArr;
    }
}
"""

_MAIN = """package com.example.gate;
public final class MainActivity {
    void onGate(BluetoothDevice device) { authenticate(device, view, 1); }
    void onAdmin(BluetoothDevice device) { authenticate(device, null, 128); }
}
"""

_ADMIN = """package com.example.gate;
public final class ManualControl {
    void open() { activity.authenticate(2, callback); }
    public void onServicesDiscovered(BluetoothGatt gatt, int status) {
        if (this.$action == 1) {
            BleManager bleManager = this.this$0.bleManager;
            if (bleManager != null) {
                bleManager.readCharacteristic(gatt, BleManager.INSTANCE.getNONCE_UUID());
                return;
            }
        }
        bleManager2.writeCharacteristic(gatt, BleManager.INSTANCE.getACTION_UUID(), new byte[]{(byte) this.$action});
    }
}
"""


def _ep(cmd: str, direction: Direction) -> Endpoint:
    return Endpoint(cmd=cmd, transport=TransportType.BLE, direction=direction)


_WRITES = [
    _ep(c, Direction.TO_DEVICE) for c in ("action", "clientKey", "clientNonce", "authenticate")
]
_READS = [_ep(c, Direction.FROM_DEVICE) for c in ("nonce", "authenticateAck", "permissions")]
_CRYPTO = [
    CryptoUsage(
        algorithm="SHA256WITHECDSA", call_site="com.example.gate.Authenticator", context_snippet=""
    )
]


def _trace(*names: str) -> SigningTrace:
    return SigningTrace(
        algorithm="SHA256WITHECDSA",
        components=[SigningComponent(kind="nonce", variable_name=n) for n in names],
        source_method="com.example.gate.Authenticator.onWrite",
        confidence=0.8,
    )


def _app(tmp_path: Path) -> Path:
    pkg = tmp_path / "sources" / "com" / "example" / "gate"
    pkg.mkdir(parents=True)
    for name, src in {
        "KeyManager": _KEYS,
        "Authenticator": _AUTH,
        "MainActivity": _MAIN,
        "ManualControl": _ADMIN,
    }.items():
        (pkg / f"{name}.java").write_text(src)
    return tmp_path


def test_complete_profile_from_code(tmp_path: Path) -> None:
    profile = build(
        "nonce",
        "authenticate",
        _WRITES,
        _READS,
        _CRYPTO,
        [_trace("nonce", "clientNonce")],
        _app(tmp_path),
        "com.example.gate",
        "MainActivity",
    )

    assert profile.missing == []
    assert (profile.ack, profile.client_key, profile.client_nonce) == (
        "authenticateAck",
        "clientKey",
        "clientNonce",
    )
    assert profile.message == ["challenge", "client_nonce"]
    assert profile.algorithm == "ecdsa-p256-sha256"
    assert (profile.signature_encoding, profile.public_key_encoding) == (
        "raw_rs",
        "sec1_compressed",
    )
    assert profile.client_nonce_length == 32
    # 1 is the launcher screen's action; 2 is admin-only; 128 authenticates without actuating
    assert (profile.primary_action, profile.probe_action) == (1, 128)
    assert profile.implicit_action == 1  # sent by skipping the action write


def test_unidentified_signed_component_is_not_guessed(tmp_path: Path) -> None:
    profile = build(
        "nonce",
        "authenticate",
        _WRITES,
        _READS,
        _CRYPTO,
        [_trace("nonce", "mysteryBytes")],
        _app(tmp_path),
        "com.example.gate",
        "MainActivity",
    )

    assert profile.message == []
    assert "message" in profile.missing


def test_no_curve_no_algorithm(tmp_path: Path) -> None:
    app = _app(tmp_path)
    (app / "sources/com/example/gate/KeyManager.java").write_text(
        _KEYS.replace('"secp256r1"', "curveName")
    )

    profile = build(
        "nonce",
        "authenticate",
        _WRITES,
        _READS,
        _CRYPTO,
        [_trace("nonce", "clientNonce")],
        app,
        "com.example.gate",
        "MainActivity",
    )

    assert profile.algorithm is None
    assert "algorithm" in profile.missing
