#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the pipeline over every cached fixture APK and compare with expectations.

For each entry in fixtures/sources.yaml whose APK is in fixtures/_cache/, runs
analyze() (static only unless --dynamic) and records the verdict:

  skip:tuya       TuyaDetectedError (P1-2 early exit)
  skip:duplicate  DuplicateFoundError (P-2.5 full coverage)
  proceed         IR extracted (plus the V-tier run status when emitting)
  error           anything else

Prints a table, writes runs/corpus-<timestamp>.json, and exits 1 when a
verdict contradicts `expected_verdict`.

Usage:  uv run python scripts/run_corpus.py [--only id1,id2] [--no-emit] [--dynamic]
        make corpus
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
import traceback
from pathlib import Path
from typing import Any

import yaml

_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from engine.pipeline import DuplicateFoundError, TuyaDetectedError, analyze  # noqa: E402

_SOURCES = _ROOT / "fixtures" / "sources.yaml"
_CACHE = _ROOT / "fixtures" / "_cache"


def _apk_path(entry: dict[str, Any]) -> Path:
    local = entry.get("local_path")
    return _ROOT / local if local else _CACHE / f"{entry['id']}.apk"


async def _run_one(entry: dict[str, Any], emit: bool, dynamic: bool) -> dict[str, Any]:
    t0 = time.time()
    row: dict[str, Any] = {"id": entry["id"], "group": entry.get("group", "")}
    try:
        ir = await analyze(_apk_path(entry), apk_id=entry["id"], emit=emit, dynamic=dynamic)
    except TuyaDetectedError:
        row["verdict"] = "skip:tuya"
    except DuplicateFoundError as exc:
        row["verdict"] = "skip:duplicate"
        row["existing"] = f"{exc.location}/{exc.integration_name}"
    except Exception as exc:  # the corpus run must survive any one APK
        row["verdict"] = "error"
        row["error"] = f"{type(exc).__name__}: {exc}"
        row["traceback"] = traceback.format_exc(limit=5)
    else:
        row.update(
            verdict="proceed",
            framework=ir.framework.value,
            transport=ir.transport.type.value,
            commands=len(ir.commands),
            events=len(ir.events),
            state_fields=len(ir.state.fields),
            confidence=ir.extraction_confidence,
            status=ir.extra.get("_status", "analysis-only"),
            existing=(
                f"{ir.duplicate_check.location}/{ir.duplicate_check.name}"
                f" ({ir.duplicate_check.coverage_estimate})"
                if ir.duplicate_check and ir.duplicate_check.found
                else ""
            ),
        )
    row["seconds"] = round(time.time() - t0, 1)
    return row


def _matches(entry: dict[str, Any], row: dict[str, Any]) -> bool | None:
    """True/False against expected_verdict; None when no expectation is recorded."""
    expected = entry.get("expected_verdict")
    if expected is None:
        return None
    if expected == "skip":
        return str(row["verdict"]).startswith("skip")
    return bool(row["verdict"] == expected)


def _print_table(rows: list[dict[str, Any]]) -> None:
    cols = [
        "id",
        "group",
        "verdict",
        "ok",
        "framework",
        "transport",
        "commands",
        "events",
        "state_fields",
        "confidence",
        "status",
        "existing",
        "seconds",
    ]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))
    for r in rows:
        if r["verdict"] == "error":
            print(f"\n{r['id']}: {r['error']}\n{r['traceback']}")


async def _main(args: argparse.Namespace) -> int:
    entries = yaml.safe_load(_SOURCES.read_text())["apks"]
    only = set(args.only.split(",")) if args.only else None
    rows: list[dict[str, Any]] = []
    for entry in entries:
        if only and entry["id"] not in only:
            continue
        if not _apk_path(entry).exists():
            print(f"skip {entry['id']}: not in fixtures/_cache (run `make fixtures`)")
            continue
        print(f"== {entry['id']}", flush=True)
        row = await _run_one(entry, emit=not args.no_emit, dynamic=args.dynamic)
        row["ok"] = {True: "yes", False: "NO", None: "-"}[_matches(entry, row)]
        rows.append(row)

    _print_table(rows)
    out = _ROOT / "runs" / f"corpus-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(rows, indent=2))
    print(f"\nWrote {out.relative_to(_ROOT)}")
    return 1 if any(r["ok"] == "NO" for r in rows) else 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", help="comma-separated fixture ids")
    parser.add_argument("--no-emit", action="store_true", help="extract only (skip P4/P5 + V-tier)")
    parser.add_argument("--dynamic", action="store_true", help="run the P2-7 oracle (redroid)")
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    sys.exit(asyncio.run(_main(parser.parse_args())))


if __name__ == "__main__":
    main()
