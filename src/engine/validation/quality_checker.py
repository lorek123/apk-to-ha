# SPDX-License-Identifier: MIT
"""V-4b — Deterministic platinum quality checkers.

Runs the 10 deterministic PLT-* rules against a rendered HACS integration
directory and returns a QualityReport.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .quality_rubric import QualityRule, deterministic_rules

_LOGGER = logging.getLogger(__name__)

_VALID_IOT_CLASSES = {
    "assumed_state",
    "cloud_polling",
    "cloud_push",
    "local_polling",
    "local_push",
    "calculated",
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
        except Exception as exc:
            _LOGGER.warning("quality_checker: %s raised %s", rule.id, exc)
            result = RuleResult(rule=rule, passed=False, detail=f"checker error: {exc}")
        results.append(result)
        _LOGGER.debug(
            "quality_checker: %s → %s %s",
            rule.id,
            "PASS" if result.passed else "FAIL",
            result.detail,
        )

    passed = not any(not r.passed and r.rule.severity == "error" for r in results)
    return QualityReport(passed=passed, results=results)


# ── individual checkers ───────────────────────────────────────────────────────


_ENTITY_CLASS = re.compile(r"^class\s+\w+\(([^)]*Entity[^)]*)\):", re.MULTILINE)


def _entity_files(d: Path) -> list[Path]:
    """Files that define entity classes (entity_base.py included)."""
    return sorted(
        py
        for py in d.glob("*.py")
        if _ENTITY_CLASS.search(py.read_text()) or py.name == "entity_base.py"
    )


def _entity_rule(d: Path, rule: QualityRule, needle: str, what: str) -> RuleResult:
    """Every entity-defining file sets *needle* itself or inherits it from entity_base.py."""
    base = d / "entity_base.py"
    base_ok = base.exists() and needle in base.read_text()
    missing = []
    for py in _entity_files(d):
        src = py.read_text()
        inherits = py.name != "entity_base.py" and "from .entity_base import" in src and base_ok
        if needle not in src and not inherits:
            missing.append(py.name)
    if not _entity_files(d):
        return RuleResult(rule=rule, passed=False, detail="no entity classes found")
    if missing:
        return RuleResult(rule=rule, passed=False, detail=f"{', '.join(missing)} missing {what}")
    return RuleResult(rule=rule, passed=True)


def _not_applicable(rule: QualityRule, why: str) -> RuleResult:
    _LOGGER.info("quality_checker: %s not applicable — %s", rule.id, why)
    return RuleResult(rule=rule, passed=True, detail=f"n/a: {why}")


def _check_entity_name(d: Path, rule: QualityRule) -> RuleResult:
    return _entity_rule(d, rule, "_attr_has_entity_name = True", "_attr_has_entity_name = True")


def _check_unique_id(d: Path, rule: QualityRule) -> RuleResult:
    return _entity_rule(d, rule, "_attr_unique_id", "_attr_unique_id")


def _check_runtime_data(d: Path, rule: QualityRule) -> RuleResult:
    init = d / "__init__.py"
    if init.exists() and "runtime_data" in init.read_text():
        return RuleResult(rule=rule, passed=True)
    return RuleResult(rule=rule, passed=False, detail="__init__.py does not use runtime_data")


def _check_aiohttp_client(d: Path, rule: QualityRule) -> RuleResult:
    sources = {py.name: py.read_text() for py in d.glob("*.py")}
    direct = [n for n, src in sources.items() if "aiohttp.ClientSession(" in src]
    if direct:
        return RuleResult(
            rule=rule, passed=False, detail=f"aiohttp.ClientSession() used directly in {direct}"
        )
    uses_http = any("aiohttp" in src or "session=" in src for src in sources.values())
    if not uses_http:
        return _not_applicable(rule, "the integration makes no HTTP/WebSocket connections")
    if any("async_get_clientsession" in src for src in sources.values()):
        return RuleResult(rule=rule, passed=True)
    return RuleResult(
        rule=rule, passed=False, detail="HTTP session not obtained via async_get_clientsession"
    )


def _check_update_failed(d: Path, rule: QualityRule) -> RuleResult:
    coord = d / "coordinator.py"
    if not coord.exists():
        return _not_applicable(rule, "no DataUpdateCoordinator (nothing is polled)")
    src = coord.read_text()
    if "UpdateFailed" in src and "raise UpdateFailed" in src:
        return RuleResult(rule=rule, passed=True)
    return RuleResult(
        rule=rule, passed=False, detail="coordinator.py does not import and raise UpdateFailed"
    )


def _check_device_info(d: Path, rule: QualityRule) -> RuleResult:
    return _entity_rule(d, rule, "identifiers=", "DeviceInfo with identifiers=")


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
    return RuleResult(
        rule=rule, passed=False, detail=f"iot_class {iot!r} not in {sorted(_VALID_IOT_CLASSES)}"
    )


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
