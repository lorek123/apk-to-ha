# SPDX-License-Identifier: MIT
"""V-4b — Deterministic platinum quality checkers.

Runs the 10 deterministic PLT-* rules against a rendered HACS integration
directory and returns a QualityReport.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .quality_rubric import QualityRule, deterministic_rules

_LOGGER = logging.getLogger(__name__)

_VALID_IOT_CLASSES = {
    "assumed_state", "cloud_polling", "cloud_push",
    "local_polling", "local_push", "calculated",
}


@dataclass
class RuleResult:
    rule: QualityRule
    passed: bool
    detail: str = ""


@dataclass
class QualityReport:
    passed: bool
    results: list[RuleResult] = field(default_factory=list)

    @property
    def failures(self) -> list[RuleResult]:
        return [r for r in self.results if not r.passed]

    @property
    def errors(self) -> list[RuleResult]:
        return [r for r in self.failures if r.rule.severity == "error"]

    @property
    def warnings(self) -> list[RuleResult]:
        return [r for r in self.failures if r.rule.severity == "warning"]


def check(integration_dir: Path) -> QualityReport:
    """Run all deterministic platinum rules against *integration_dir*."""
    rules = deterministic_rules()
    results: list[RuleResult] = []

    for rule in rules:
        fn = _CHECKERS.get(rule.id)
        if fn is None:
            _LOGGER.debug("quality_checker: no checker for %s — skipped", rule.id)
            continue
        try:
            result = fn(integration_dir, rule)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.warning("quality_checker: %s raised %s", rule.id, exc)
            result = RuleResult(rule=rule, passed=False, detail=f"checker error: {exc}")
        results.append(result)
        _LOGGER.debug("quality_checker: %s → %s %s", rule.id, "PASS" if result.passed else "FAIL", result.detail)

    passed = not any(not r.passed and r.rule.severity == "error" for r in results)
    return QualityReport(passed=passed, results=results)


# ── individual checkers ───────────────────────────────────────────────────────

def _check_entity_name(d: Path, rule: QualityRule) -> RuleResult:
    base = d / "entity_base.py"
    if base.exists() and "_attr_has_entity_name = True" in base.read_text():
        return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail="entity_base.py missing _attr_has_entity_name = True")


def _check_unique_id(d: Path, rule: QualityRule) -> RuleResult:
    base = d / "entity_base.py"
    if base.exists() and "_attr_unique_id" in base.read_text():
        return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail="entity_base.py missing _attr_unique_id")


def _check_runtime_data(d: Path, rule: QualityRule) -> RuleResult:
    init = d / "__init__.py"
    if init.exists() and "runtime_data" in init.read_text():
        return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail="__init__.py does not use runtime_data")


def _check_aiohttp_client(d: Path, rule: QualityRule) -> RuleResult:
    for filename in ("__init__.py", "config_flow.py"):
        f = d / filename
        if f.exists() and "async_get_clientsession" in f.read_text():
            return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail="async_get_clientsession not found in __init__.py or config_flow.py")


def _check_update_failed(d: Path, rule: QualityRule) -> RuleResult:
    coord = d / "coordinator.py"
    if coord.exists():
        src = coord.read_text()
        if "UpdateFailed" in src and "raise UpdateFailed" in src:
            return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail="coordinator.py does not import and raise UpdateFailed")


def _check_device_info(d: Path, rule: QualityRule) -> RuleResult:
    base = d / "entity_base.py"
    if base.exists():
        src = base.read_text()
        if "DeviceInfo" in src and "identifiers=" in src:
            return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail="entity_base.py missing DeviceInfo with identifiers=")


def _check_spdx_headers(d: Path, rule: QualityRule) -> RuleResult:
    missing = []
    for py in d.rglob("*.py"):
        lines = py.read_text().splitlines()
        if not lines or "SPDX-License-Identifier" not in lines[0]:
            missing.append(str(py.relative_to(d)))
    if not missing:
        return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail=f"missing SPDX header: {', '.join(missing)}")


def _check_config_flow_user_step(d: Path, rule: QualityRule) -> RuleResult:
    cf = d / "config_flow.py"
    if not cf.exists():
        return RuleResult(rule=rule, passed=False, detail="config_flow.py missing")
    src = cf.read_text()
    issues = []
    if "async_step_user" not in src:
        issues.append("async_step_user missing")
    if "errors" not in src:
        issues.append("errors dict missing")
    if "async_show_form" not in src:
        issues.append("async_show_form missing")
    if issues:
        return RuleResult(rule=rule, passed=False, detail="; ".join(issues))
    return RuleResult(rule=rule, passed=True)


def _check_iot_class(d: Path, rule: QualityRule) -> RuleResult:
    mf = d / "manifest.json"
    if not mf.exists():
        return RuleResult(rule=rule, passed=False, detail="manifest.json missing")
    try:
        data = json.loads(mf.read_text())
    except json.JSONDecodeError as exc:
        return RuleResult(rule=rule, passed=False, detail=f"manifest.json invalid JSON: {exc}")
    iot = data.get("iot_class")
    if iot in _VALID_IOT_CLASSES:
        return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail=f"iot_class {iot!r} not in {sorted(_VALID_IOT_CLASSES)}")


def _check_translation_coverage(d: Path, rule: QualityRule) -> RuleResult:
    strings = d / "strings.json"
    en = d / "translations" / "en.json"
    issues = []
    for label, path in (("strings.json", strings), ("translations/en.json", en)):
        if not path.exists():
            issues.append(f"{label} missing")
            continue
        try:
            json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            issues.append(f"{label} invalid JSON: {exc}")
    if issues:
        return RuleResult(rule=rule, passed=False, detail="; ".join(issues))
    return RuleResult(rule=rule, passed=True)


# ── checker registry ──────────────────────────────────────────────────────────

_CHECKERS: dict[str, Callable[[Path, QualityRule], RuleResult]] = {
    "PLT-001": _check_entity_name,
    "PLT-002": _check_unique_id,
    "PLT-003": _check_runtime_data,
    "PLT-004": _check_aiohttp_client,
    "PLT-005": _check_update_failed,
    "PLT-006": _check_device_info,
    "PLT-007": _check_spdx_headers,
    "PLT-008": _check_config_flow_user_step,
    "PLT-009": _check_iot_class,
    "PLT-010": _check_translation_coverage,
}
