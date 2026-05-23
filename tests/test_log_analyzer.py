# SPDX-License-Identifier: MIT
"""Tests for V-7 HA log analyzer."""
from __future__ import annotations

from engine.validation.log_analyzer import LogFinding, analyze, summary


def test_empty_output_returns_no_findings() -> None:
    assert analyze("") == []


def test_clean_output_returns_no_findings() -> None:
    output = "V3_IMPORT_OK\nIntegration loaded successfully.\n"
    assert analyze(output) == []


def test_detects_import_error_traceback() -> None:
    output = (
        "Traceback (most recent call last):\n"
        "  File 'test.py', line 1, in <module>\n"
        "ImportError: No module named 'missing_sdk'\n"
    )
    findings = analyze(output)
    cats = {f.category for f in findings}
    assert "import_error" in cats


def test_detects_module_not_found() -> None:
    output = "ModuleNotFoundError: No module named 'mydevice_sdk'\n"
    findings = analyze(output)
    assert any(f.category == "import_error" for f in findings)
    assert any(f.severity == "error" for f in findings)


def test_detects_setup_failure() -> None:
    output = "Setup failed for mydevice: ConfigEntryNotReady\n"
    findings = analyze(output)
    assert any(f.category == "setup_failure" for f in findings)


def test_detects_config_entry_not_ready() -> None:
    output = "homeassistant.exceptions.ConfigEntryNotReady: device not reachable\n"
    findings = analyze(output)
    assert any(f.category in ("import_error", "setup_failure") for f in findings)


def test_detects_async_violation() -> None:
    output = "WARNING (MainThread) [homeassistant.util.async_] Detected blocking call to open\n"
    findings = analyze(output)
    assert any(f.category == "async_violation" for f in findings)
    assert any(f.severity == "warning" for f in findings)


def test_detects_deprecation() -> None:
    output = "DeprecationWarning: async_setup is deprecated, use async_setup_entry\n"
    findings = analyze(output)
    assert any(f.category == "deprecation" for f in findings)


def test_detects_schema_error() -> None:
    output = "voluptuous.error.Invalid: required key not provided @ data['host']\n"
    findings = analyze(output)
    assert any(f.category == "schema_error" for f in findings)


def test_deduplication_suppresses_repeated_lines() -> None:
    line = "ImportError: No module named 'sdk'\n"
    output = line * 5
    findings = analyze(output)
    import_errors = [f for f in findings if f.category == "import_error"]
    assert len(import_errors) == 1


def test_summary_counts_by_category() -> None:
    output = (
        "ImportError: No module named 'a'\n"
        "ImportError: No module named 'b'\n"
        "DeprecationWarning: old api used\n"
    )
    findings = analyze(output)
    counts = summary(findings)
    assert counts.get("import_error", 0) >= 1
    assert counts.get("deprecation", 0) >= 1


def test_finding_has_required_fields() -> None:
    output = "ImportError: missing module\n"
    findings = analyze(output)
    assert findings
    f = findings[0]
    assert isinstance(f, LogFinding)
    assert f.category
    assert f.severity in ("error", "warning")
    assert f.message
    assert f.raw_line
