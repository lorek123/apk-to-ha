# SPDX-License-Identifier: MIT
"""Tests for F-2a snapshot destinations."""

from __future__ import annotations

from pathlib import Path

import pytest

import engine.snapshot.harness as harness
from engine.ir.models import (
    AuthScheme,
    AuthType,
    DiscoveryMechanism,
    DiscoveryType,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)


def _ir() -> ProtocolIR:
    return ProtocolIR(
        apk_path="app.apk",
        package_name="com.example.device",
        app_name="Device",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(),
    )


def test_explicit_dir_leaves_committed_snapshot_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    committed = tmp_path / "fixtures"
    monkeypatch.setattr(harness, "_SNAPSHOTS_DIR", committed)
    run_snap = tmp_path / "runs" / "abc123" / "snapshot"

    out = harness.write("device", _ir(), tmp_path / "jadx", run_snap)

    assert out == run_snap
    assert (run_snap / "ir.json").exists()
    assert not committed.exists()


def test_default_is_committed_location(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(harness, "_SNAPSHOTS_DIR", tmp_path)

    out = harness.write("device", _ir(), tmp_path / "jadx")

    assert out == harness.committed_dir("device") == tmp_path / "device"
    assert harness.load("device").package_name == "com.example.device"
