# SPDX-License-Identifier: MIT
"""V-4a — Quality rubric loader.

Reads config/quality_rubric.yaml and exposes typed QualityRule objects.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml  # type: ignore[import-untyped]

_RUBRIC_PATH = Path(__file__).parents[3] / "config" / "quality_rubric.yaml"


@dataclass(frozen=True)
class QualityRule:
    id: str
    name: str
    description: str
    check_type: str   # "deterministic" | "agent"
    severity: str     # "error" | "warning"


def load() -> list[QualityRule]:
    """Return all rules from the rubric YAML."""
    with _RUBRIC_PATH.open() as fh:
        data = yaml.safe_load(fh)
    return [QualityRule(**r) for r in data["rules"]]


def deterministic_rules() -> list[QualityRule]:
    """Return only the rules that have deterministic checkers."""
    return [r for r in load() if r.check_type == "deterministic"]


def coverage() -> dict[str, QualityRule]:
    """Return all rules keyed by their id."""
    return {r.id: r for r in load()}
