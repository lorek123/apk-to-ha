# SPDX-License-Identifier: MIT
"""Golden emission: each committed IR must emit exactly its committed tree.

A failure after an intended template change: run `make golden` and review the
diff. Otherwise the change altered generated integrations by accident.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.emitters import golden

_CASES = sorted(p for p in golden.GOLDEN_DIR.iterdir() if (p / "ir.json").exists())


def test_cases_exist() -> None:
    assert len(_CASES) >= 4


@pytest.mark.parametrize("case_dir", _CASES, ids=[p.name for p in _CASES])
def test_emission_matches_golden(case_dir: Path, tmp_path: Path) -> None:
    golden.emit(golden.load_ir(case_dir), tmp_path)

    difference = golden.diff(golden.tree(case_dir / "expected"), golden.tree(tmp_path))

    assert not difference, f"emission changed (run `make golden` if intended):\n{difference}"


@pytest.mark.parametrize("case_dir", _CASES, ids=[p.name for p in _CASES])
def test_golden_ir_is_sanitised(case_dir: Path) -> None:
    ir = golden.load_ir(case_dir)

    assert ir.apk_path == f"{case_dir.name}.apk"
    assert not [k for k in ir.extra if k.startswith("_")]


def test_diff_reports_changes() -> None:
    out = golden.diff({"a.py": "x = 1\n", "b.py": ""}, {"a.py": "x = 2\n", "c.py": ""})

    assert "missing: b.py" in out
    assert "unexpected: c.py" in out
    assert "-x = 1" in out
    assert "+x = 2" in out
