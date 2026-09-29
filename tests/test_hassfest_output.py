# SPDX-License-Identifier: MIT
"""Tests for parsing the official hassfest image's report (V-2)."""

from __future__ import annotations

from engine.validation.hassfest import parse_hassfest_output

_REPORT = """\
Validating manifest... done in 0.00s
Validating translations... done in 0.01s

Integrations: 1
Invalid integrations: 1

Integration r2d2 - /github/workspace/custom_components/r2d2:
* [ERROR] [MANIFEST] Invalid manifest: not a valid option at 'homeassistant'. Got '2026.9.0'
* [WARNING] [TRANSLATIONS] Unused translation key 'config.step.foo'
"""


def test_parses_errors_and_warnings() -> None:
    findings = parse_hassfest_output(_REPORT)

    assert findings is not None
    assert [(f.severity, f.check) for f in findings] == [
        ("error", "hassfest:manifest"),
        ("warning", "hassfest:translations"),
    ]
    assert findings[0].message.startswith("Invalid manifest: not a valid option")


def test_clean_report_has_no_findings() -> None:
    assert parse_hassfest_output("Validating json... done\n\nIntegrations: 1\n") == []


def test_non_report_output_means_hassfest_did_not_run() -> None:
    assert parse_hassfest_output("docker: Error response from daemon: pull failed") is None
