# SPDX-License-Identifier: MIT
"""Iteration budgets for the V-tier fix loop (SPECIFICATION.md §8).

- Per-issue fix attempts: 3. A finding still present after 3 fix attempts is
  not converging — stop patching symptoms and surface it (CLAUDE.md).
- Total run cap: 10 fix cycles, then halt with ``needs-human-review``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .hassfest import Finding
from .ruff_check import RuffFinding

MAX_ATTEMPTS_PER_FINDING = 3
MAX_FIX_CYCLES = 10


def finding_key(finding: RuffFinding | Finding) -> str:
    """Stable identity for a finding across loop iterations.

    Line numbers are left out on purpose: a fix that shifts lines must not make
    an unfixed finding look new.
    """
    if isinstance(finding, RuffFinding):
        return f"ruff:{finding.code}:{Path(finding.file).name}:{finding.message}"
    return f"{finding.check}:{finding.message}"


@dataclass
class FindingTracker:
    """Counts how many fix cycles each blocking finding has survived."""

    max_attempts: int = MAX_ATTEMPTS_PER_FINDING
    attempts: Counter[str] = field(default_factory=Counter)

    def record(self, keys: list[str]) -> None:
        """Record one fix attempt against each finding still present."""
        self.attempts.update(set(keys))

    def exhausted(self, keys: list[str]) -> list[str]:
        """Findings in *keys* that have used up their attempts, sorted."""
        return sorted(k for k in set(keys) if self.attempts[k] >= self.max_attempts)
