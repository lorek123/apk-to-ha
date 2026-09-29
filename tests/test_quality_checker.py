# SPDX-License-Identifier: MIT
"""Tests for V-4b platinum quality checker."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engine.validation.quality_checker import check
from engine.validation.quality_rubric import QualityRule, coverage, deterministic_rules, load

# ── rubric loader ─────────────────────────────────────────────────────────────


def test_load_returns_rules() -> None:
    rules = load()
    assert len(rules) >= 12


def test_all_rules_have_required_fields() -> None:
    for r in load():
        assert r.id.startswith("PLT-")
        assert r.name
        assert r.description
        assert r.check_type in ("deterministic", "agent")
        assert r.severity in ("error", "warning")


def test_deterministic_rules_subset() -> None:
    det = deterministic_rules()
    assert len(det) == 10
    assert all(r.check_type == "deterministic" for r in det)


def test_coverage_keyed_by_id() -> None:
    cov = coverage()
    assert "PLT-001" in cov
    assert isinstance(cov["PLT-001"], QualityRule)


# ── helper: build a minimal valid integration dir ─────────────────────────────


def _make_integration(tmp_path: Path, **overrides: Any) -> Path:
    """Create a minimal platinum-compliant integration under tmp_path."""
    d = tmp_path / "custom_components" / "mydevice"
    d.mkdir(parents=True)
    (d / "translations").mkdir()

    files: dict[str, str] = {
        "__init__.py": (
            "# SPDX-License-Identifier: MIT\n"
            "from homeassistant.helpers import aiohttp_client\n"
            "entry.runtime_data = None\n"
            "aiohttp_client.async_get_clientsession(hass)\n"
        ),
        "entity_base.py": (
            "# SPDX-License-Identifier: MIT\n"
            "from homeassistant.helpers.device_registry import DeviceInfo\n"
            "_attr_has_entity_name = True\n"
            "_attr_unique_id = 'stub'\n"
            "DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})\n"
        ),
        "coordinator.py": (
            "# SPDX-License-Identifier: MIT\n"
            "from homeassistant.helpers.update_coordinator import UpdateFailed\n"
            "raise UpdateFailed('error')\n"
        ),
        "config_flow.py": (
            "# SPDX-License-Identifier: MIT\n"
            "async def async_step_user(self, user_input=None):\n"
            "    errors = {}\n"
            "    return self.async_show_form(step_id='user', errors=errors)\n"
        ),
        "manifest.json": json.dumps(
            {
                "domain": "mydevice",
                "name": "My Device",
                "iot_class": "local_push",
                "version": "0.1.0",
            }
        ),
        "strings.json": json.dumps({"config": {"step": {"user": {"title": "Connect"}}}}),
    }
    (d / "translations" / "en.json").write_text(
        json.dumps({"config": {"step": {"user": {"title": "Connect"}}}})
    )

    files.update(overrides)
    for name, content in files.items():
        (d / name).write_text(content)

    return d


# ── check() function ──────────────────────────────────────────────────────────


def test_check_passes_for_valid_integration(tmp_path: Path) -> None:
    d = _make_integration(tmp_path)
    report = check(d)
    assert report.passed, [r.detail for r in report.errors]


def test_check_fails_plt001_missing_entity_name(tmp_path: Path) -> None:
    d = _make_integration(
        tmp_path,
        **{
            "entity_base.py": (
                "# SPDX-License-Identifier: MIT\n"
                "_attr_unique_id = 'stub'\n"
                "DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})\n"
            )
        },
    )
    report = check(d)
    ids = {r.rule.id for r in report.errors}
    assert "PLT-001" in ids


def test_check_fails_plt002_missing_unique_id(tmp_path: Path) -> None:
    d = _make_integration(
        tmp_path,
        **{
            "entity_base.py": (
                "# SPDX-License-Identifier: MIT\n"
                "_attr_has_entity_name = True\n"
                "DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})\n"
            )
        },
    )
    report = check(d)
    ids = {r.rule.id for r in report.errors}
    assert "PLT-002" in ids


def test_check_fails_plt003_missing_runtime_data(tmp_path: Path) -> None:
    d = _make_integration(
        tmp_path,
        **{
            "__init__.py": (
                "# SPDX-License-Identifier: MIT\n"
                "from homeassistant.helpers import aiohttp_client\n"
                "aiohttp_client.async_get_clientsession(hass)\n"
            )
        },
    )
    report = check(d)
    ids = {r.rule.id for r in report.errors}
    assert "PLT-003" in ids


def test_check_fails_plt004_missing_aiohttp_client(tmp_path: Path) -> None:
    d = _make_integration(
        tmp_path,
        **{
            "__init__.py": "# SPDX-License-Identifier: MIT\nentry.runtime_data = None\n",
            "config_flow.py": (
                "# SPDX-License-Identifier: MIT\n"
                "async def async_step_user(self, user_input=None):\n"
                "    errors = {}\n"
                "    return self.async_show_form(step_id='user', errors=errors)\n"
            ),
        },
    )
    report = check(d)
    ids = {r.rule.id for r in report.errors}
    assert "PLT-004" in ids


def test_check_fails_plt005_missing_update_failed(tmp_path: Path) -> None:
    d = _make_integration(
        tmp_path, **{"coordinator.py": ("# SPDX-License-Identifier: MIT\n# no UpdateFailed here\n")}
    )
    report = check(d)
    ids = {r.rule.id for r in report.errors}
    assert "PLT-005" in ids


def test_check_fails_plt007_missing_spdx(tmp_path: Path) -> None:
    d = _make_integration(tmp_path, **{"coordinator.py": "# no spdx header\npass\n"})
    report = check(d)
    ids = {r.rule.id for r in report.errors}
    assert "PLT-007" in ids


def test_check_fails_plt009_invalid_iot_class(tmp_path: Path) -> None:
    d = _make_integration(
        tmp_path,
        **{
            "manifest.json": json.dumps(
                {
                    "domain": "mydevice",
                    "name": "My Device",
                    "iot_class": "magic_cloud",
                    "version": "0.1.0",
                }
            )
        },
    )
    report = check(d)
    ids = {r.rule.id for r in report.errors}
    assert "PLT-009" in ids


def test_check_warns_plt010_invalid_strings_json(tmp_path: Path) -> None:
    d = _make_integration(tmp_path, **{"strings.json": "NOT JSON {"})
    report = check(d)
    ids = {r.rule.id for r in report.warnings}
    assert "PLT-010" in ids


def test_quality_report_properties(tmp_path: Path) -> None:
    d = _make_integration(
        tmp_path,
        **{
            "manifest.json": json.dumps(
                {
                    "domain": "mydevice",
                    "name": "My Device",
                    "iot_class": "bogus",
                    "version": "0.1.0",
                }
            )
        },
    )
    report = check(d)
    assert not report.passed
    assert len(report.errors) >= 1
    assert all(r.rule.severity == "error" for r in report.errors)


def test_check_tolerates_missing_optional_files(tmp_path: Path) -> None:
    """integration_dir with only mandatory files should not crash."""
    d = tmp_path / "custom_components" / "bare"
    d.mkdir(parents=True)
    (d / "translations").mkdir()
    (d / "__init__.py").write_text(
        "# SPDX-License-Identifier: MIT\n"
        "entry.runtime_data = None\n"
        "aiohttp_client.async_get_clientsession(hass)\n"
    )
    (d / "manifest.json").write_text(json.dumps({"domain": "bare", "iot_class": "local_push"}))
    (d / "strings.json").write_text("{}")
    (d / "translations" / "en.json").write_text("{}")
    report = check(d)
    assert isinstance(report.passed, bool)
