# SPDX-License-Identifier: MIT
"""Tests for evidence-based extraction confidence and oracle confirmation."""

from __future__ import annotations

from pathlib import Path

from engine.dynamic.capture_model import CaptureSession, WsCapture
from engine.dynamic.ir_reconciler import reconcile
from engine.extraction import confidence
from engine.extraction.protocol_scanner import ProtocolScanner
from engine.ir.models import (
    AuthScheme,
    AuthType,
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

_API = """package com.example.device;
public class DeviceApi {
    public static final String SET_LEVEL = "set_level";
    public static final String ROBOT_NO_RESPONSE_COMMAND_LIST =
        new ArrayList(Arrays.asList(STATE_PUSH));
    public static final String STATE_PUSH = "state_push";

    public Request ping() {
        JSONObject o = new JSONObject();
        o.put("cmd", "ping");
        return createRequest(o);
    }

    public Request setLevel(int level) {
        JSONObject o = new JSONObject();
        o.put("cmd", SET_LEVEL);
        o.put("level", level);
        return createRequest(o);
    }

    void mode(int n) {
        action_dance();
        o.put("mode", 3);
    }
}
"""


def _scan(tmp_path: Path) -> tuple[list[Endpoint], list[Endpoint], StateSchema]:
    pkg = tmp_path / "sources" / "com" / "example" / "device"
    pkg.mkdir(parents=True)
    (pkg / "DeviceApi.java").write_text(_API)
    _, _, _, state, commands, events = ProtocolScanner(tmp_path).scan("com.example.device")
    return commands, events, state


def test_scores_reflect_evidence(tmp_path: Path) -> None:
    commands, _, _ = _scan(tmp_path)
    by_cmd = {c.cmd: c.confidence for c in commands}

    # Name certain, request fields guessed from nearby put() calls.
    assert by_cmd["set_level"] == confidence.score(
        confidence.NAME_CMD_PUT, confidence.FIELDS_NEARBY
    )
    # Name certain, no fields found (absence isn't proof).
    assert by_cmd["ping"] == confidence.score(confidence.NAME_CMD_PUT, confidence.FIELDS_NONE)
    # Static evidence alone stays below the oracle's 0.9 threshold.
    assert max(by_cmd.values()) < 0.9


def test_summary_mean_and_weak_notes() -> None:
    eps = [
        Endpoint(
            cmd="a",
            transport=TransportType.WEBSOCKET,
            direction=Direction.TO_DEVICE,
            confidence=0.9,
        ),
        Endpoint(
            cmd="b",
            transport=TransportType.WEBSOCKET,
            direction=Direction.TO_DEVICE,
            confidence=0.5,
        ),
    ]

    overall, notes = confidence.summarize(eps)

    assert overall == 0.7
    assert notes == ["low confidence (<0.7): b"]
    assert confidence.summarize([]) == (0.0, ["no endpoints extracted"])


def test_oracle_confirmation_raises_confidence() -> None:
    ir = ProtocolIR(
        apk_path="app.apk",
        package_name="com.example.device",
        app_name="Device",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(),
        commands=[
            Endpoint(
                cmd="ping",
                transport=TransportType.WEBSOCKET,
                direction=Direction.TO_DEVICE,
                confidence=0.81,
            ),
            Endpoint(
                cmd="never_seen",
                transport=TransportType.WEBSOCKET,
                direction=Direction.TO_DEVICE,
                confidence=0.81,
            ),
        ],
    )
    session = CaptureSession(ws_frames=[WsCapture(direction="send", frame='{"cmd":"ping"}')])

    report = reconcile(session, ir)

    assert report.confirmed_commands == ["ping"]
    assert report.patched_ir is not None
    scores = {c.cmd: c.confidence for c in report.patched_ir.commands}
    assert scores == {"ping": confidence.OBSERVED, "never_seen": 0.81}
