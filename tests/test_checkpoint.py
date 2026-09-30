# SPDX-License-Identifier: MIT
"""IR checkpoints: --from-checkpoint skips P1-P3 and reuses the last extraction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from engine import pipeline
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
        apk_path="a.apk",
        package_name="com.example.device",
        app_name="Device",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.HTTP_REST),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(),
    )


def _apk(tmp_path: Path, content: bytes = b"apk-v1") -> Path:
    apk = tmp_path / "device.apk"
    apk.write_bytes(content)
    return apk


def _logger() -> tuple[list[tuple[str, str]], Any]:
    seen: list[tuple[str, str]] = []

    def log(phase: str, step: str, level: str, message: str, **ctx: object) -> None:
        seen.append((level, message))

    return seen, log


def test_round_trip(tmp_path: Path) -> None:
    apk, ckpt = _apk(tmp_path), tmp_path / "ckpt" / "device.json"
    pipeline._save_checkpoint(ckpt, apk, _ir())
    seen, log = _logger()

    assert pipeline._load_checkpoint(ckpt, apk, log) == _ir()
    assert not any(level == "WARNING" for level, _ in seen)


def test_missing_checkpoint(tmp_path: Path) -> None:
    with pytest.raises(pipeline.CheckpointError, match="no checkpoint"):
        pipeline._load_checkpoint(tmp_path / "none.json", _apk(tmp_path), _logger()[1])


def test_checkpoint_from_another_apk_is_refused(tmp_path: Path) -> None:
    ckpt = tmp_path / "device.json"
    pipeline._save_checkpoint(ckpt, _apk(tmp_path), _ir())

    with pytest.raises(pipeline.CheckpointError, match="different APK"):
        pipeline._load_checkpoint(ckpt, _apk(tmp_path, b"apk-v2"), _logger()[1])


def test_stale_extractor_code_warns(tmp_path: Path) -> None:
    apk, ckpt = _apk(tmp_path), tmp_path / "device.json"
    pipeline._save_checkpoint(ckpt, apk, _ir())
    payload = json.loads(ckpt.read_text())
    ckpt.write_text(json.dumps({**payload, "extractor_hash": "older"}))
    seen, log = _logger()

    pipeline._load_checkpoint(ckpt, apk, log)

    assert any(level == "WARNING" and "stale" in msg for level, msg in seen)


async def test_analyze_from_checkpoint_skips_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pipeline, "_CHECKPOINT_DIR", tmp_path / "ckpt")
    monkeypatch.setattr(pipeline, "_RUNS_DIR", tmp_path / "runs")
    apk = _apk(tmp_path)
    pipeline._save_checkpoint(tmp_path / "ckpt" / "device.json", apk, _ir())

    async def no_extract(*args: object, **kwargs: object) -> ProtocolIR:
        raise AssertionError("extraction must not run")

    monkeypatch.setattr(pipeline, "_extract", no_extract)

    ir = await pipeline.analyze(apk, apk_id="device", emit=False, from_checkpoint=True)

    assert ir.package_name == "com.example.device"
    (run,) = (tmp_path / "runs").iterdir()
    assert json.loads((run / "summary.json").read_text())["status"] == "analysis-only"


async def test_analyze_saves_a_checkpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pipeline, "_CHECKPOINT_DIR", tmp_path / "ckpt")
    monkeypatch.setattr(pipeline, "_RUNS_DIR", tmp_path / "runs")

    async def extract(*args: object, **kwargs: object) -> ProtocolIR:
        return _ir()

    monkeypatch.setattr(pipeline, "_extract", extract)

    await pipeline.analyze(_apk(tmp_path), apk_id="device", emit=False)

    assert (tmp_path / "ckpt" / "device.json").exists()
