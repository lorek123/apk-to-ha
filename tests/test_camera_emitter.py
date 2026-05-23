# SPDX-License-Identifier: MIT
"""Tests for camera platform emission: context builder and template rendering."""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from engine.emitters.context import build, _platforms
from engine.emitters import hacs_emitter, sdk_emitter
from engine.extraction.entity_classifier import classify
from engine.ir.models import (
    AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
    Framework, ProtocolIR, StateSchema, StreamingContract,
    TransportContract, TransportType,
)
from engine.validation import ruff_check


def _minimal_ir(**overrides: Any) -> ProtocolIR:
    """Return a minimal ProtocolIR sufficient for context.build()."""
    base: dict[str, Any] = {
        "apk_path": "synthetic",
        "package_name": "com.example.mycam",
        "app_name": "MyCam",
        "framework": Framework.NATIVE,
        "transport": TransportContract(
            type=TransportType.WEBSOCKET, port=8887, host_source="discovered",
        ),
        "discovery": DiscoveryMechanism(type=DiscoveryType.UDP_BROADCAST, port=5555),
        "auth": AuthScheme(type=AuthType.NONE),
        "state": StateSchema(),
    }
    base.update(overrides)
    return ProtocolIR(**base)


# ── context: no streaming ────────────────────────────────────────────────────

def test_no_camera_when_streaming_none() -> None:
    ir = _minimal_ir()
    ctx = build(ir)
    assert ctx["has_camera"] is False
    assert "camera" not in ctx["platforms"]


def test_video_port_zero_when_no_streaming() -> None:
    ir = _minimal_ir()
    ctx = build(ir)
    assert ctx["video_port"] == 0


# ── context: with streaming ───────────────────────────────────────────────────

def test_has_camera_when_streaming_set() -> None:
    ir = _minimal_ir(streaming=StreamingContract(port=12121))
    ctx = build(ir)
    assert ctx["has_camera"] is True


def test_camera_in_platforms_when_streaming() -> None:
    ir = _minimal_ir(streaming=StreamingContract(port=12121))
    ctx = build(ir)
    assert "camera" in ctx["platforms"]


def test_video_port_in_context() -> None:
    ir = _minimal_ir(streaming=StreamingContract(port=12121))
    ctx = build(ir)
    assert ctx["video_port"] == 12121


def test_video_frame_format_in_context() -> None:
    ir = _minimal_ir(streaming=StreamingContract(port=12121, frame_format="jpeg"))
    ctx = build(ir)
    assert ctx["video_frame_format"] == "jpeg"


def test_video_rotate_degrees_in_context() -> None:
    ir = _minimal_ir(streaming=StreamingContract(port=12121, rotate_degrees=90))
    ctx = build(ir)
    assert ctx["video_rotate_degrees"] == 90


# ── _platforms helper ─────────────────────────────────────────────────────────

def test_platforms_includes_camera_flag() -> None:
    plats = _platforms([], [], [], [], [], [], has_camera=True)
    assert "camera" in plats


def test_platforms_excludes_camera_by_default() -> None:
    plats = _platforms([], [], [], [], [], [])
    assert "camera" not in plats


# ── template rendering ────────────────────────────────────────────────────────

def test_camera_hacs_template_renders(tmp_path: Path) -> None:
    ir = classify(_minimal_ir(streaming=StreamingContract(port=12121)))
    ctx = build(ir)
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)
    camera_py = hacs_dir / "camera.py"
    assert camera_py.exists(), "camera.py was not emitted"
    content = camera_py.read_text()
    assert "async_camera_image" in content
    assert "VideoStreamClient" in content
    assert "12121" in content


def test_camera_sdk_template_renders(tmp_path: Path) -> None:
    ir = classify(_minimal_ir(streaming=StreamingContract(port=12121)))
    ctx = build(ir)
    sdk_dir = sdk_emitter.emit(ctx, tmp_path)
    video_stream_py = sdk_dir / "video_stream.py"
    assert video_stream_py.exists(), "video_stream.py was not emitted"
    content = video_stream_py.read_text()
    assert "VideoStreamClient" in content
    assert "stream" in content
    assert "12121" in content


def test_no_camera_py_when_no_streaming(tmp_path: Path) -> None:
    ir = classify(_minimal_ir())
    ctx = build(ir)
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)
    assert not (hacs_dir / "camera.py").exists()


def test_no_video_stream_py_when_no_streaming(tmp_path: Path) -> None:
    ir = classify(_minimal_ir())
    ctx = build(ir)
    sdk_dir = sdk_emitter.emit(ctx, tmp_path)
    assert not (sdk_dir / "video_stream.py").exists()


# ── ruff check ────────────────────────────────────────────────────────────────

def test_camera_emitter_output_passes_ruff(tmp_path: Path) -> None:
    """Emitted camera.py must be ruff-clean."""
    ir = classify(_minimal_ir(streaming=StreamingContract(port=12121, rotate_degrees=90)))
    ctx = build(ir)
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)

    ruff_result = asyncio.run(ruff_check.check(hacs_dir))
    assert ruff_result.passed, (
        f"ruff found {ruff_result.error_count} errors:\n"
        + "\n".join(
            f"  {f.file}:{f.line} [{f.code}] {f.message}"
            for f in ruff_result.findings
        )
    )


def test_video_stream_sdk_passes_ruff(tmp_path: Path) -> None:
    """Emitted video_stream.py must be ruff-clean."""
    ir = classify(_minimal_ir(streaming=StreamingContract(port=12121)))
    ctx = build(ir)
    sdk_dir = sdk_emitter.emit(ctx, tmp_path)

    ruff_result = asyncio.run(ruff_check.check(sdk_dir))
    assert ruff_result.passed, (
        f"ruff found {ruff_result.error_count} errors:\n"
        + "\n".join(
            f"  {f.file}:{f.line} [{f.code}] {f.message}"
            for f in ruff_result.findings
        )
    )
