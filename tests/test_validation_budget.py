# SPDX-License-Identifier: MIT
"""Tests for V-loop honesty: real fix counts, SDK routing, budgets, run status."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.pipeline import _run_status
from engine.validation import ruff_check
from engine.validation.budget import FindingTracker, finding_key
from engine.validation.fix_router import route_and_apply
from engine.validation.hassfest import Finding
from engine.validation.ruff_check import RuffFinding

_UNSORTED = "# SPDX-License-Identifier: MIT\nimport sys\nimport os\n\nprint(os, sys)\n"


def _ruff_finding(path: Path, code: str = "I001") -> RuffFinding:
    return RuffFinding(file=str(path), line=2, col=1, code=code, message="Import block")


# ── fix_router: real counts + SDK routing ─────────────────────────────────────


def test_ruff_fix_reports_real_count(tmp_path: Path) -> None:
    hacs = tmp_path / "hacs"
    hacs.mkdir()
    bad = hacs / "sensor.py"
    bad.write_text(_UNSORTED)

    result = route_and_apply([_ruff_finding(bad)], [], {}, hacs)

    assert result.applied == 1
    assert bad.read_text().index("import os") < bad.read_text().index("import sys")


def test_ruff_fix_with_nothing_to_fix_applies_zero(tmp_path: Path) -> None:
    hacs = tmp_path / "hacs"
    hacs.mkdir()
    clean = hacs / "sensor.py"
    clean.write_text("# SPDX-License-Identifier: MIT\nimport os\n\nprint(os)\n")

    # A stale finding for a file that is already clean must not count as progress.
    result = route_and_apply([_ruff_finding(clean)], [], {}, hacs)

    assert result.applied == 0


def test_sdk_findings_are_fixed_in_sdk_dir(tmp_path: Path) -> None:
    hacs = tmp_path / "hacs"
    sdk = tmp_path / "sdk"
    hacs.mkdir()
    sdk.mkdir()
    bad = sdk / "client.py"
    bad.write_text(_UNSORTED)

    result = route_and_apply([_ruff_finding(bad)], [], {}, hacs, sdk_dir=sdk)

    assert result.applied == 1
    assert any("sdk" in d for d in result.details)
    assert bad.read_text().index("import os") < bad.read_text().index("import sys")


# ── ruff_check: tool errors are failures ──────────────────────────────────────


async def test_ruff_tool_error_is_not_a_pass(tmp_path: Path) -> None:
    # An invalid config makes ruff itself fail (rc=2) instead of reporting findings.
    (tmp_path / "ruff.toml").write_text("line-length = 'not-a-number'\n")
    (tmp_path / "a.py").write_text("x = 1\n")
    result = await ruff_check.check(tmp_path)

    assert not result.passed
    assert result.tool_error


# ── budget tracker ────────────────────────────────────────────────────────────


def test_finding_key_ignores_line_numbers(tmp_path: Path) -> None:
    a = RuffFinding(file=str(tmp_path / "x.py"), line=3, col=1, code="F821", message="undef")
    b = RuffFinding(file=str(tmp_path / "x.py"), line=9, col=4, code="F821", message="undef")

    assert finding_key(a) == finding_key(b)
    assert finding_key(Finding("error", "spdx", "a.py: missing")) == "spdx:a.py: missing"


def test_tracker_exhausts_after_max_attempts() -> None:
    tracker = FindingTracker(max_attempts=3)
    keys = ["ruff:F821:x.py:undef", "spdx:a.py"]

    for _ in range(2):
        tracker.record(keys)
    assert tracker.exhausted(keys) == []

    tracker.record(["ruff:F821:x.py:undef"])  # spdx got fixed in between
    assert tracker.exhausted(keys) == ["ruff:F821:x.py:undef"]


def test_tracker_counts_duplicates_once_per_cycle() -> None:
    tracker = FindingTracker(max_attempts=2)
    tracker.record(["k", "k", "k"])

    assert tracker.exhausted(["k"]) == []


# ── run status ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("unresolved", "passed", "v3", "skipped", "expected"),
    [
        ([], [True, True], True, [], "pass"),
        ([], [True, True], None, ["V3"], "incomplete"),
        ([], [True, False], True, [], "fail"),
        ([], [True, True], False, [], "fail"),
        (["ruff:F821:x.py:undef"], [False, True], True, [], "needs-human-review"),
    ],
)
def test_run_status(
    unresolved: list[str],
    passed: list[bool],
    v3: bool | None,
    skipped: list[str],
    expected: str,
) -> None:
    assert _run_status(unresolved, passed, v3, skipped) == expected
