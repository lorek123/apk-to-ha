# SPDX-License-Identifier: MIT
"""Tests for the structural hassfest validator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from engine.validation.hassfest import (
    Finding,
    _check_config_flow,
    _check_manifest,
    _check_platforms,
    _check_platinum,
    _check_spdx,
)


def _write(d: Path, name: str, content: str) -> None:
    (d / name).write_text(content)


def _good_manifest(domain: str = "test") -> dict[str, Any]:
    return {
        "domain": domain,
        "name": "Test Device",
        "codeowners": [],
        "config_flow": True,
        "documentation": "https://example.com",
        "homeassistant": "2026.5.0",
        "iot_class": "local_push",
        "quality_scale": "platinum",
        "requirements": [],
        "version": "0.1.0",
    }


# ── manifest checks ───────────────────────────────────────────────────────────


def test_manifest_missing(tmp_path: Path) -> None:
    findings: list[Finding] = []
    _check_manifest(tmp_path, findings)
    assert any(f.severity == "error" and "missing" in f.message for f in findings)


def test_manifest_valid(tmp_path: Path) -> None:
    (tmp_path / "translations").mkdir()
    _write(tmp_path, "manifest.json", json.dumps(_good_manifest()))
    _write(tmp_path, "strings.json", "{}")
    _write(tmp_path / "translations", "en.json", "{}")
    findings: list[Finding] = []
    _check_manifest(tmp_path, findings)
    assert not any(f.severity == "error" for f in findings)


def test_manifest_missing_key(tmp_path: Path) -> None:
    m = _good_manifest()
    del m["iot_class"]
    _write(tmp_path, "manifest.json", json.dumps(m))
    findings: list[Finding] = []
    _check_manifest(tmp_path, findings)
    assert any("iot_class" in f.message for f in findings)


def test_manifest_bad_iot_class(tmp_path: Path) -> None:
    m = _good_manifest()
    m["iot_class"] = "magic_push"
    _write(tmp_path, "manifest.json", json.dumps(m))
    findings: list[Finding] = []
    _check_manifest(tmp_path, findings)
    assert any("iot_class" in f.message for f in findings)


def test_manifest_missing_translations(tmp_path: Path) -> None:
    _write(tmp_path, "manifest.json", json.dumps(_good_manifest()))
    findings: list[Finding] = []
    _check_manifest(tmp_path, findings)
    assert any("translations/en.json" in f.message for f in findings)


# ── platform checks ───────────────────────────────────────────────────────────


def test_platform_missing_setup_entry(tmp_path: Path) -> None:
    _write(tmp_path, "manifest.json", json.dumps(_good_manifest()))
    _write(tmp_path, "sensor.py", "# no setup entry here\n")
    findings: list[Finding] = []
    _check_platforms(tmp_path, findings)
    assert any("sensor.py" in f.message for f in findings)


def test_platform_has_setup_entry(tmp_path: Path) -> None:
    _write(tmp_path, "manifest.json", json.dumps(_good_manifest()))
    _write(tmp_path, "sensor.py", "async def async_setup_entry(hass, entry, add): pass\n")
    findings: list[Finding] = []
    _check_platforms(tmp_path, findings)
    assert not any("sensor.py" in f.message for f in findings)


# ── config flow checks ────────────────────────────────────────────────────────


def test_config_flow_missing(tmp_path: Path) -> None:
    findings: list[Finding] = []
    _check_config_flow(tmp_path, findings)
    assert any("config_flow.py missing" in f.message for f in findings)


def test_config_flow_valid(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "config_flow.py",
        """
class TestConfigFlow(ConfigFlow, domain="test"):
    async def async_step_user(self, user_input=None): pass
""",
    )
    findings: list[Finding] = []
    _check_config_flow(tmp_path, findings)
    assert not any(f.severity == "error" for f in findings)


# ── SPDX checks ───────────────────────────────────────────────────────────────


def test_spdx_missing(tmp_path: Path) -> None:
    _write(tmp_path, "sensor.py", "# no spdx header\n")
    findings: list[Finding] = []
    _check_spdx(tmp_path, findings)
    assert any("SPDX" in f.message for f in findings)


def test_spdx_present(tmp_path: Path) -> None:
    _write(tmp_path, "sensor.py", "# SPDX-License-Identifier: MIT\n")
    findings: list[Finding] = []
    _check_spdx(tmp_path, findings)
    assert not findings


# ── platinum via base class ───────────────────────────────────────────────────


def test_platinum_via_base_class(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "entity_base.py",
        "class Base:\n    _attr_has_entity_name = True\n    _attr_unique_id = None\n",
    )
    _write(tmp_path, "sensor.py", "from .entity_base import Base\nclass MySensor(Base): pass\n")
    findings: list[Finding] = []
    _check_platinum(tmp_path, findings)
    assert not any(f.severity == "warning" for f in findings)


# ── generated integration smoke test ─────────────────────────────────────────


def test_generated_r2d2_passes_structural() -> None:
    """The integration we generated from the R2-D2 snapshot must pass all structural checks."""
    import asyncio

    from engine.validation.hassfest import validate

    hacs_dir = (
        Path(__file__).parents[1] / "sdk_output/bullb_r2d2/custom_components/r2d2"
    ).resolve()
    if not hacs_dir.exists():
        pytest.skip("generated integration not present — run the pipeline first")
    result = asyncio.run(validate(hacs_dir))
    errors = [f.message for f in result.errors]
    assert result.passed, "Structural checks failed:\n" + "\n".join(errors)
