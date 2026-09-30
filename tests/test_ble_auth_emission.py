# SPDX-License-Identifier: MIT
"""Tests for BLE challenge-response emission: gating, rendered code, key handling."""

from __future__ import annotations

import importlib.util
import py_compile
import subprocess
import sys
from pathlib import Path

from engine.emitters import context as ctx_mod
from engine.emitters import hacs_emitter, sdk_emitter
from engine.ir.models import (
    AuthScheme,
    AuthType,
    ChallengeResponseProfile,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)

_UUIDS = {
    "nonce": "00000100-0000-1000-8000-00805f9b34fb",
    "authenticate": "00000101-0000-1000-8000-00805f9b34fb",
    "clientKey": "00000102-0000-1000-8000-00805f9b34fb",
    "clientNonce": "00000103-0000-1000-8000-00805f9b34fb",
    "authenticateAck": "00000105-0000-1000-8000-00805f9b34fb",
    "action": "00000106-0000-1000-8000-00805f9b34fb",
}


def _ir(**profile_overrides: object) -> ProtocolIR:
    profile = ChallengeResponseProfile(
        challenge="nonce",
        proof="authenticate",
        ack="authenticateAck",
        client_key="clientKey",
        client_nonce="clientNonce",
        client_nonce_length=32,
        message=["challenge", "client_nonce"],
        algorithm="ecdsa-p256-sha256",
        signature_encoding="raw_rs",
        public_key_encoding="sec1_compressed",
        action="action",
        primary_action=1,
        probe_action=128,
        implicit_action=1,
    ).model_copy(update=profile_overrides)
    return ProtocolIR(
        apk_path="a.apk",
        package_name="org.example.gate",
        app_name="Gate",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.BLE),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.CHALLENGE_RESPONSE, challenge=profile),
        state=StateSchema(),
        commands=[
            Endpoint(cmd=c, transport=TransportType.BLE, direction=Direction.TO_DEVICE)
            for c in ("action", "authenticate", "clientKey", "clientNonce")
        ],
        extra={
            "ble_char_uuids": _UUIDS,
            "ble_service_uuids": ["6a7e6a7e-4929-42d0-0000-fcc5a35e13f1"],
        },
    )


def test_incomplete_profile_is_not_emittable() -> None:
    assert ctx_mod.challenge_ctx(_ir()) is not None
    assert ctx_mod.challenge_ctx(_ir(algorithm=None)) is None  # missing piece
    ir = _ir()
    ir.extra["ble_char_uuids"] = {k: v for k, v in _UUIDS.items() if k != "authenticateAck"}
    assert ctx_mod.challenge_ctx(ir) is None  # a role without a UUID


def test_rendered_integration_compiles_and_lints(tmp_path: Path) -> None:
    ctx = ctx_mod.build(_ir())
    sdk_dir = sdk_emitter.emit(ctx, tmp_path)
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)
    tests_dir = hacs_emitter.emit_tests(ctx, tmp_path)
    assert tests_dir is not None

    assert {p.name for p in hacs_dir.glob("*.py")} == {
        "__init__.py", "button.py", "config_flow.py", "const.py", "diagnostics.py",
    }  # fmt: skip
    for py in [*sdk_dir.glob("*.py"), *hacs_dir.glob("*.py"), *tests_dir.glob("*.py")]:
        py_compile.compile(str(py), doraise=True)
        assert py.read_text().startswith("# SPDX-License-Identifier: MIT"), py
    ruff = subprocess.run(
        ["ruff", "check", "--select", "E,F,W,I", "--ignore", "E501", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ruff.returncode == 0, ruff.stdout


def test_auth_module_keys_and_signatures(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    sdk_dir = sdk_emitter.emit(ctx_mod.build(_ir()), tmp_path)
    spec = importlib.util.spec_from_file_location("gate_auth", sdk_dir / "auth.py")
    assert spec and spec.loader
    auth = importlib.util.module_from_spec(spec)
    sys.modules["gate_auth"] = auth
    spec.loader.exec_module(auth)

    pem = auth.generate_private_key()
    assert pem != auth.generate_private_key()  # fresh key each time
    public = bytes.fromhex(auth.public_key_hex(pem))
    assert len(public) == 33 and public[0] in (2, 3)  # compressed SEC1

    challenge, client_nonce = b"c" * 32, auth.new_client_nonce()
    assert len(client_nonce) == 32 and client_nonce != auth.new_client_nonce()
    sig = auth.sign(auth.load_private_key(pem), auth.signed_message(challenge, client_nonce))
    assert len(sig) == 64  # raw r‖s
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public).verify(
        der, challenge + client_nonce, ec.ECDSA(hashes.SHA256())
    )

    for bad in (b"", b"x" * 65):  # we don't sign out-of-protocol challenges
        try:
            auth.signed_message(bad, client_nonce)
        except auth.AuthProtocolError:
            continue
        raise AssertionError(f"signed a {len(bad)}-byte challenge")

    other = ec.generate_private_key(ec.SECP384R1())
    from cryptography.hazmat.primitives import serialization

    wrong_curve = other.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    try:
        auth.load_private_key(wrong_curve)
    except auth.AuthProtocolError as exc:
        assert "PRIVATE KEY" not in str(exc)  # never echoes key material
    else:
        raise AssertionError("accepted a key on the wrong curve")
