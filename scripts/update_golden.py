#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rewrite the golden emission trees (tests/golden/<case>/expected/).

Run after an intended template or emitter change, then review the diff in git.

  --refresh-ir  first replace each case's ir.json with the app's latest
                extraction (.cache/checkpoints/<case>.json, or the committed
                snapshot for cases without a cached APK)

Usage:  uv run python scripts/update_golden.py [--refresh-ir] [--only case1,case2]
        make golden
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from engine.emitters.golden import GOLDEN_DIR, sanitise, write_expected  # noqa: E402
from engine.ir.models import ProtocolIR  # noqa: E402

_CHECKPOINTS = _ROOT / ".cache" / "checkpoints"
_SNAPSHOTS = _ROOT / "fixtures" / "snapshots"


def _latest_ir(case: str) -> ProtocolIR | None:
    checkpoint = _CHECKPOINTS / f"{case}.json"
    if checkpoint.exists():
        return ProtocolIR.model_validate(json.loads(checkpoint.read_text())["ir"])
    snapshot = _SNAPSHOTS / case / "ir.json"
    if snapshot.exists():
        return ProtocolIR.model_validate_json(snapshot.read_text())
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--refresh-ir", action="store_true")
    parser.add_argument("--only", help="comma-separated case names")
    args = parser.parse_args()
    only = set(args.only.split(",")) if args.only else None

    for case_dir in sorted(p for p in GOLDEN_DIR.iterdir() if p.is_dir()):
        case = case_dir.name
        if only and case not in only:
            continue
        if args.refresh_ir:
            ir = _latest_ir(case)
            if ir is None:
                print(f"{case}: no checkpoint or snapshot; keeping ir.json")
            else:
                (case_dir / "ir.json").write_text(sanitise(ir, case).model_dump_json(indent=2))
        write_expected(case_dir)
        print(f"{case}: expected/ rewritten")


if __name__ == "__main__":
    main()
