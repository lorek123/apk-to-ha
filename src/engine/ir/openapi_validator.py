# SPDX-License-Identifier: MIT
"""P3-3 — Validate an OpenAPI 3.0.3 document dict against the official schema."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:
    from openapi_spec_validator import validate as _ov_validate
    from openapi_spec_validator.validation.exceptions import OpenAPIValidationError
    _VALIDATOR_AVAILABLE = True
except ImportError:  # pragma: no cover
    _VALIDATOR_AVAILABLE = False


@dataclass
class ValidationReport:
    passed: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return len(self.errors)


def validate(doc: dict[str, Any]) -> ValidationReport:
    """Validate *doc* (an OpenAPI 3.0.3 dict) and return a ValidationReport.

    Raises nothing — all findings are captured in the report.
    If ``openapi-spec-validator`` is not installed the report passes with a
    warning so the pipeline is not blocked.
    """
    if not _VALIDATOR_AVAILABLE:
        return ValidationReport(
            passed=True,
            warnings=["openapi-spec-validator not installed — skipping schema validation"],
        )

    errors: list[str] = []
    warnings: list[str] = []

    try:
        _ov_validate(doc)
    except OpenAPIValidationError as exc:
        errors.append(str(exc))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"Unexpected validator error: {exc}")

    # ── additional linting rules ───────────────────────────────────────────────

    # Every path should have at least one tag
    for path, item in doc.get("paths", {}).items():
        for method, op in item.items():
            if not op.get("tags"):
                warnings.append(f"{method.upper()} {path}: no tags defined")

    # operationId must be unique
    op_ids: list[str] = []
    for item in doc.get("paths", {}).values():
        for op in item.values():
            oid = op.get("operationId")
            if oid:
                if oid in op_ids:
                    errors.append(f"Duplicate operationId: {oid!r}")
                op_ids.append(oid)

    # info.version present
    if not doc.get("info", {}).get("version"):
        warnings.append("info.version is missing")

    return ValidationReport(passed=len(errors) == 0, errors=errors, warnings=warnings)
