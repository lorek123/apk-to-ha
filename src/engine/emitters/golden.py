# SPDX-License-Identifier: MIT
"""Golden emission cases: a committed IR per app, and the exact tree it must emit.

tests/golden/<case>/ir.json    input (sanitised: no absolute paths or run state)
tests/golden/<case>/expected/  SDK + HACS integration + runtime tests, as emitted

tests/test_golden.py re-emits every case and diffs it against expected/;
scripts/update_golden.py rewrites expected/ after an intended template change.
"""

from __future__ import annotations

import difflib
import json
import shutil
from pathlib import Path

from ..ir.models import ProtocolIR
from . import context, emit_all

GOLDEN_DIR = Path(__file__).parents[3] / "tests" / "golden"


def sanitise(ir: ProtocolIR, case: str) -> ProtocolIR:
    """Drop what varies between machines and runs (paths, "_"-prefixed run state)."""
    extra = {k: v for k, v in ir.extra.items() if not k.startswith("_")}
    return ir.model_copy(update={"apk_path": f"{case}.apk", "extra": extra})


def load_ir(case_dir: Path) -> ProtocolIR:
    return ProtocolIR.model_validate(json.loads((case_dir / "ir.json").read_text()))


def emit(ir: ProtocolIR, out_root: Path) -> None:
    """Emit everything the pipeline emits for *ir* into *out_root*."""
    emit_all(context.build(ir), out_root)


def write_expected(case_dir: Path) -> None:
    expected = case_dir / "expected"
    shutil.rmtree(expected, ignore_errors=True)
    emit(load_ir(case_dir), expected)


def tree(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): p.read_text()
        for p in sorted(root.rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts
    }


def diff(expected: dict[str, str], actual: dict[str, str], limit: int = 80) -> str:
    """Readable difference between two emitted trees ("" when identical)."""
    lines: list[str] = []
    for path in sorted(expected.keys() - actual.keys()):
        lines.append(f"missing: {path}")
    for path in sorted(actual.keys() - expected.keys()):
        lines.append(f"unexpected: {path}")
    for path in sorted(expected.keys() & actual.keys()):
        if expected[path] != actual[path]:
            lines += difflib.unified_diff(
                expected[path].splitlines(),
                actual[path].splitlines(),
                f"expected/{path}",
                f"emitted/{path}",
                lineterm="",
            )
    if len(lines) > limit:
        lines = [*lines[:limit], f"... {len(lines) - limit} more lines"]
    return "\n".join(lines)
