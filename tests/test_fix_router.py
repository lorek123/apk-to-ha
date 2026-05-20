# SPDX-License-Identifier: MIT
"""Tests for V-5 fix router (deterministic strategies)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine.validation.fix_router import route_and_apply
from engine.validation.hassfest import Finding
from engine.validation.ruff_check import RuffFinding


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_integration(tmp_path: Path, *, iot_class: str = "local_push") -> Path:
    """Minimal integration directory that passes structural checks."""
    d = tmp_path / "custom_components" / "myapp"
    d.mkdir(parents=True)
    (d / "translations").mkdir()

    manifest = {
        "domain": "myapp",
        "name": "My App",
        "codeowners": [],
        "config_flow": True,
        "documentation": "https://example.com",
        "homeassistant": "2026.1.0",
        "iot_class": iot_class,
        "quality_scale": "platinum",
        "requirements": ["myapp_sdk==0.1.0"],
        "version": "0.1.0",
    }
    (d / "manifest.json").write_text(json.dumps(manifest, indent=2))
    (d / "translations" / "en.json").write_text("{}")
    (d / "strings.json").write_text("{}")
    (d / "__init__.py").write_text("# SPDX-License-Identifier: MIT\n")
    return d


def _base_ctx() -> dict:
    return {
        "domain": "myapp",
        "name": "My App",
        "class_prefix": "Myapp",
        "sdk_package": "myapp_sdk",
        "integration_version": "0.1.0",
        "ha_min_version": "2026.1.0",
        "iot_class": "local_polling",
        "ws_port": 8887,
        "udp_port": None,
        "udp_broadcast_cmd": None,
        "auth_cmd": "grantAccess",
        "state_push_cmd": "gin",
        "switches": [],
        "buttons": [],
        "selects": [],
        "numbers": [],
        "sensors": [],
        "binary_sensors": [],
        "mode_actions": {},
        "platforms": [],
    }


# ── iot_class patch ───────────────────────────────────────────────────────────

def test_patches_invalid_iot_class(tmp_path):
    d = _make_integration(tmp_path, iot_class="cloud_magic")
    ctx = {**_base_ctx(), "iot_class": "local_polling"}

    finding = Finding(
        severity="error",
        check="manifest",
        message="iot_class 'cloud_magic' not in ['assumed_state', ...]",
    )
    result = route_and_apply([], [finding], ctx, d)

    assert result.applied == 1
    data = json.loads((d / "manifest.json").read_text())
    assert data["iot_class"] == "local_polling"


def test_no_patch_when_iot_class_already_valid(tmp_path):
    d = _make_integration(tmp_path, iot_class="local_push")
    ctx = {**_base_ctx(), "iot_class": "local_push"}

    # No findings at all → nothing applied
    result = route_and_apply([], [], ctx, d)
    assert result.applied == 0


# ── missing manifest key ──────────────────────────────────────────────────────

def test_patches_missing_manifest_key(tmp_path):
    d = _make_integration(tmp_path)
    manifest = json.loads((d / "manifest.json").read_text())
    del manifest["version"]
    (d / "manifest.json").write_text(json.dumps(manifest))
    ctx = {**_base_ctx(), "integration_version": "0.2.0"}

    finding = Finding(
        severity="error",
        check="manifest",
        message="manifest.json missing required key: 'version'",
    )
    result = route_and_apply([], [finding], ctx, d)

    assert result.applied == 1
    data = json.loads((d / "manifest.json").read_text())
    assert data["version"] == "0.2.0"


def test_skips_unknown_manifest_key(tmp_path):
    d = _make_integration(tmp_path)
    ctx = _base_ctx()

    finding = Finding(
        severity="error",
        check="manifest",
        message="manifest.json missing required key: 'secret_key'",
    )
    result = route_and_apply([], [finding], ctx, d)

    assert result.applied == 0
    assert result.skipped == 1


# ── SPDX header ───────────────────────────────────────────────────────────────

def test_prepends_spdx_header(tmp_path):
    d = _make_integration(tmp_path)
    sensor = d / "sensor.py"
    sensor.write_text('"""Sensor platform."""\n')

    finding = Finding(
        severity="error",
        check="spdx",
        message="sensor.py: missing SPDX header",
    )
    result = route_and_apply([], [finding], _base_ctx(), d)

    assert result.applied == 1
    first_line = sensor.read_text().splitlines()[0]
    assert "SPDX-License-Identifier" in first_line


def test_spdx_not_prepended_twice(tmp_path):
    d = _make_integration(tmp_path)
    # __init__.py already has the header from _make_integration
    finding = Finding(
        severity="error",
        check="spdx",
        message="__init__.py: missing SPDX header",
    )
    result = route_and_apply([], [finding], _base_ctx(), d)

    # File already had it → no change, returns 0 (prepend returns False)
    assert result.applied == 0


# ── warnings are skipped ──────────────────────────────────────────────────────

def test_warnings_not_counted_as_errors(tmp_path):
    d = _make_integration(tmp_path)
    finding = Finding(
        severity="warning",
        check="manifest",
        message="quality_scale 'diamond' unrecognised",
    )
    result = route_and_apply([], [finding], _base_ctx(), d)

    assert result.applied == 0
    assert result.skipped == 0  # warnings are silently skipped


# ── ruff fixable detection ────────────────────────────────────────────────────

def test_ruff_fixable_codes_are_routed():
    from engine.validation.fix_router import _is_ruff_fixable
    assert _is_ruff_fixable("I001")
    assert _is_ruff_fixable("F401")
    assert _is_ruff_fixable("W291")
    assert not _is_ruff_fixable("E711")
    assert not _is_ruff_fixable("F811")


def test_unfixable_ruff_findings_are_skipped(tmp_path):
    d = _make_integration(tmp_path)
    finding = RuffFinding(
        file=str(d / "sensor.py"),
        line=5,
        col=1,
        code="E711",
        message="comparison to None (use 'is' or 'is not')",
    )
    result = route_and_apply([finding], [], _base_ctx(), d)

    assert result.applied == 0
    assert result.skipped == 1


# ── iot_class inference from context ─────────────────────────────────────────

def test_context_iot_class_http_rest():
    from engine.emitters.context import _infer_iot_class
    from engine.ir.models import TransportType
    assert _infer_iot_class(TransportType.HTTP_REST) == "local_polling"
    assert _infer_iot_class(TransportType.WEBSOCKET) == "local_push"
    assert _infer_iot_class(TransportType.BLE) == "local_push"
    assert _infer_iot_class(TransportType.UDP) == "local_push"
