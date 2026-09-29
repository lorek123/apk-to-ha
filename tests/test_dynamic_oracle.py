# SPDX-License-Identifier: MIT
"""Tests for P2-7 dynamic protocol oracle (unit tests — no Docker required)."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest

from engine.dynamic.capture_model import (
    CaptureSession,
    HmacCapture,
    HttpCapture,
    WsCapture,
)
from engine.dynamic.ir_reconciler import (
    _extract_commands_from_session,
    reconcile,
)
from engine.ir.models import (
    AuthScheme,
    AuthType,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    FieldDef,
    FieldKind,
    Framework,
    ProtocolIR,
    SigningComponent,
    SigningTrace,
    StateSchema,
    TransportContract,
    TransportType,
)

# ── fixtures ──────────────────────────────────────────────────────────────────


def _make_ir(**overrides: Any) -> ProtocolIR:
    defaults = dict(
        apk_path="/tmp/test.apk",
        package_name="com.example.device",
        app_name="Test Device",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887),
        discovery=DiscoveryMechanism(type=DiscoveryType.UDP_BROADCAST, port=12345),
        auth=AuthScheme(type=AuthType.HANDSHAKE, handshake_cmd="grantAccess"),
        state=StateSchema(push_cmd="gin"),
        commands=[
            Endpoint(
                cmd="powerControl",
                transport=TransportType.WEBSOCKET,
                direction=Direction.TO_DEVICE,
                request_fields=[
                    FieldDef(name="enable", kind=FieldKind.BOOLEAN),
                ],
            ),
        ],
        events=[],
        signing_traces=[
            SigningTrace(
                algorithm="HMAC-SHA256",
                components=[
                    SigningComponent(kind="timestamp", variable_name="ts", confidence=0.8),
                    SigningComponent(kind="literal", variable_name="", value="\n", confidence=1.0),
                    SigningComponent(kind="path", variable_name="path", confidence=0.8),
                ],
                key_source="apiKey",
                source_method="com.example.Signer.sign",
                confidence=0.75,
                unresolved=[],
            ),
        ],
    )
    defaults.update(overrides)
    return ProtocolIR(**defaults)


def _make_hmac_capture(key: str, message: str, algo: str = "HmacSHA256") -> HmacCapture:
    digest = hashlib.sha256 if "256" in algo else hashlib.sha1
    key_bytes = key.encode()
    msg_bytes = message.encode()
    output = hmac.new(key_bytes, msg_bytes, digest).digest()
    return HmacCapture(
        algorithm=algo,
        key_hex=key_bytes.hex(),
        input_hex=msg_bytes.hex(),
        output_hex=output.hex(),
    )


# ── CaptureSession ────────────────────────────────────────────────────────────


def test_capture_session_is_empty() -> None:
    assert CaptureSession().is_empty


def test_capture_session_not_empty_with_hmac() -> None:
    s = CaptureSession(hmac_calls=[_make_hmac_capture("key", "msg")])
    assert not s.is_empty


def test_ws_sends_and_recvs_filter() -> None:
    s = CaptureSession(
        ws_frames=[
            WsCapture(direction="send", frame='{"cmd":"auth"}'),
            WsCapture(direction="recv", frame='{"cmd":"state"}'),
        ]
    )
    assert len(s.ws_sends()) == 1
    assert len(s.ws_recvs()) == 1


# ── _extract_commands_from_session ────────────────────────────────────────────


def test_extract_commands_from_ws_send() -> None:
    s = CaptureSession(
        ws_frames=[
            WsCapture(direction="send", frame='{"cmd":"powerControl","enable":true}'),
            WsCapture(direction="send", frame='{"cmd":"setMode","mode":1}'),
        ]
    )
    cmds = _extract_commands_from_session(s)
    assert "powerControl" in cmds
    assert "setMode" in cmds


def test_extract_commands_from_http() -> None:
    s = CaptureSession(
        http_calls=[
            HttpCapture(method="POST", url="http://192.168.1.5:8080/api/v1/powerControl"),
        ]
    )
    cmds = _extract_commands_from_session(s)
    assert "powerControl" in cmds


def test_extract_commands_ignores_invalid_json() -> None:
    s = CaptureSession(
        ws_frames=[
            WsCapture(direction="send", frame="not valid json"),
        ]
    )
    cmds = _extract_commands_from_session(s)
    assert len(cmds) == 0


# ── reconcile: signing verification ──────────────────────────────────────────


def test_reconcile_signing_verified() -> None:
    ir = _make_ir()
    capture = _make_hmac_capture("my_secret_key", "1234567890\n/api/v1/cmd")
    s = CaptureSession(hmac_calls=[capture])
    report = reconcile(s, ir)
    assert report.signing is not None
    assert report.signing.verified
    assert report.confidence_boost > 0


def test_reconcile_signing_mismatch_no_crash() -> None:
    ir = _make_ir()
    # Wrong output — mismatch but should not raise
    capture = HmacCapture(
        algorithm="HmacSHA256",
        key_hex=b"key".hex(),
        input_hex=b"message".hex(),
        output_hex=b"wrong_output_wrong_output_wrong!".hex(),
    )
    s = CaptureSession(hmac_calls=[capture])
    report = reconcile(s, ir)
    assert report.signing is not None
    assert not report.signing.verified


def test_reconcile_empty_session_returns_empty_report() -> None:
    ir = _make_ir()
    report = reconcile(CaptureSession(), ir)
    assert report.patched_ir is None
    assert report.confidence_boost == 0.0


# ── reconcile: new commands ───────────────────────────────────────────────────


def test_reconcile_finds_new_command() -> None:
    ir = _make_ir()
    s = CaptureSession(
        ws_frames=[
            WsCapture(direction="send", frame='{"cmd":"brightnessControl","level":80}'),
        ]
    )
    report = reconcile(s, ir)
    assert "brightnessControl" in report.new_commands


def test_reconcile_no_false_new_commands_for_known() -> None:
    ir = _make_ir()
    s = CaptureSession(
        ws_frames=[
            WsCapture(direction="send", frame='{"cmd":"powerControl","enable":true}'),
        ]
    )
    report = reconcile(s, ir)
    assert "powerControl" not in report.new_commands


def test_reconcile_patched_ir_includes_new_command() -> None:
    ir = _make_ir()
    s = CaptureSession(
        ws_frames=[
            WsCapture(direction="send", frame='{"cmd":"newCmd"}'),
        ]
    )
    report = reconcile(s, ir)
    assert report.patched_ir is not None
    cmd_names = [ep.cmd for ep in report.patched_ir.commands]
    assert "newCmd" in cmd_names


# ── reconcile: auth cmd correction ────────────────────────────────────────────


def test_reconcile_corrects_auth_cmd() -> None:
    ir = _make_ir()  # auth_cmd = "grantAccess"
    s = CaptureSession(
        ws_frames=[
            WsCapture(direction="send", frame='{"cmd":"auth","token":"abc"}'),
        ]
    )
    report = reconcile(s, ir)
    assert report.auth_cmd_correction == "auth"
    assert report.patched_ir is not None
    assert report.patched_ir.auth.handshake_cmd == "auth"


def test_reconcile_no_auth_correction_when_matches() -> None:
    ir = _make_ir()
    s = CaptureSession(
        ws_frames=[
            WsCapture(direction="send", frame='{"cmd":"grantAccess","uuid":"123"}'),
        ]
    )
    report = reconcile(s, ir)
    assert report.auth_cmd_correction is None


# ── reconcile: confidence boost ───────────────────────────────────────────────


def test_reconcile_confidence_boost_applied_to_trace() -> None:
    ir = _make_ir()
    capture = _make_hmac_capture("secret", "1234567890\n/api/v1/cmd")
    s = CaptureSession(hmac_calls=[capture])
    report = reconcile(s, ir)
    if report.patched_ir and report.signing and report.signing.verified:
        new_conf = report.patched_ir.signing_traces[0].confidence
        assert new_conf > ir.signing_traces[0].confidence


# ── oracle._should_skip ────────────────────────────────────────────────────────


def test_oracle_skip_when_high_confidence() -> None:
    from engine.dynamic.oracle import _should_skip

    ir = _make_ir(
        signing_traces=[
            SigningTrace(
                algorithm="HMAC-SHA256",
                components=[SigningComponent(kind="timestamp", variable_name="ts")],
                key_source="key",
                source_method="com.example.Signer.sign",
                confidence=0.95,
                unresolved=[],
            ),
        ]
    )
    assert _should_skip(ir)


def test_oracle_no_skip_when_low_confidence() -> None:
    from engine.dynamic.oracle import _should_skip

    ir = _make_ir()  # confidence=0.75
    assert not _should_skip(ir)


def test_oracle_no_skip_when_unresolved() -> None:
    from engine.dynamic.oracle import _should_skip

    ir = _make_ir(
        signing_traces=[
            SigningTrace(
                algorithm="HMAC-SHA256",
                components=[],
                key_source="key",
                source_method="com.example.Signer.sign",
                confidence=0.95,
                unresolved=["mystery_var"],
            ),
        ]
    )
    assert not _should_skip(ir)


# ── mock_device_server ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mock_device_server_starts_and_stops() -> None:
    from engine.dynamic.mock_device_server import mock_device

    async with mock_device(ws_port=18887, udp_port=None) as server:
        assert server.ws_port == 18887


@pytest.mark.asyncio
async def test_mock_device_server_responds_to_ws_auth() -> None:
    import aiohttp

    from engine.dynamic.mock_device_server import mock_device

    async with mock_device(ws_port=18888, udp_port=None, auth_cmd="grantAccess"):
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect("ws://localhost:18888/") as ws:
                await ws.send_str(json.dumps({"cmd": "grantAccess", "uuid": "test"}))
                msg = await ws.receive(timeout=3)
                data = json.loads(msg.data)
                assert data["cmd"] == "grantAccess"
                assert data["result"] == "ok"
