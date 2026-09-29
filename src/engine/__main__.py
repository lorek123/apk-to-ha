# SPDX-License-Identifier: MIT
"""CLI: python -m engine analyze <apk_path> [--id <apk_id>]"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from .pipeline import DuplicateFoundError, TuyaDetectedError, analyze

# Run statuses that make the CLI exit non-zero ("incomplete" = a validator was skipped).
_FAILING_STATUSES = frozenset({"fail", "needs-human-review"})

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def main() -> None:
    parser = argparse.ArgumentParser(prog="engine", description="APK → HA integration pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("analyze", help="Run P1→P-2.5→P3→snapshot on an APK")
    p.add_argument("apk", type=Path, help="Path to the .apk file")
    p.add_argument(
        "--id", dest="apk_id", default=None, help="Override fixture ID (default: apk stem)"
    )
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument(
        "--no-dynamic",
        dest="dynamic",
        action="store_false",
        help="Skip the P2-7 dynamic oracle (redroid + Frida); static analysis only",
    )
    p.add_argument(
        "--update-snapshots",
        action="store_true",
        help="Refresh the committed fixtures/snapshots/<id>/ (default: runs/<run_id>/snapshot/)",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.cmd == "analyze":
        if not args.apk.exists():
            print(f"ERROR: {args.apk} does not exist", file=sys.stderr)
            sys.exit(1)

        try:
            ir = asyncio.run(
                analyze(
                    args.apk,
                    apk_id=args.apk_id,
                    dynamic=args.dynamic,
                    update_snapshots=args.update_snapshots,
                )
            )
        except TuyaDetectedError as exc:
            print(f"\n⚠  Tuya SDK detected in {exc}.")
            print("   This device is already supported via tinytuya / HA Core 'tuya' integration.")
            print("   Pipeline halted — no integration generated.")
            sys.exit(2)
        except DuplicateFoundError as exc:
            print(f"\n⚠  {exc}.")
            print("   Pipeline halted — no integration generated.")
            sys.exit(2)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            if args.verbose:
                raise
            sys.exit(1)

        print("\n✓ Extraction complete")
        print(f"  Package:    {ir.package_name}")
        print(f"  Framework:  {ir.framework.value}")
        print(f"  Transport:  {ir.transport.type.value}  port={ir.transport.port}")
        print(f"  Discovery:  {ir.discovery.type.value}  port={ir.discovery.port}")
        print(f"  Auth:       {ir.auth.type.value}  ({ir.auth.handshake_cmd or 'n/a'})")
        print(f"  Commands:   {len(ir.commands)}")
        print(f"  Events:     {len(ir.events)}")
        print(f"  State fields: {len(ir.state.fields)}")
        if ir.duplicate_check and ir.duplicate_check.found:
            print(
                f"  ⚠  Duplicate: {ir.duplicate_check.location}/{ir.duplicate_check.name}"
                f" ({ir.duplicate_check.coverage_estimate} coverage)"
            )
        print(f"\n  Snapshot:   {ir.extra.get('_snapshot_dir')}")
        if "_sdk_dir" in ir.extra:
            print(f"  SDK:        {ir.extra['_sdk_dir']}")
            print(f"  HACS:       {ir.extra['_hacs_dir']}")
        if "_v1_passed" in ir.extra:
            v1s = "PASS" if ir.extra["_v1_passed"] else "FAIL"
            print(
                f"\n  V-1 ruff:              {v1s} — {ir.extra['_v1_errors']} errors, "
                f"{ir.extra['_v1_warnings']} warnings"
            )
        if "_v2_passed" in ir.extra:
            status = "PASS" if ir.extra["_v2_passed"] else "FAIL"
            tier = ir.extra["_v2_tier"]
            nerr = len(ir.extra.get("_v2_errors", []))
            nwrn = len(ir.extra.get("_v2_warnings", []))
            print(f"  V-2 hassfest ({tier}): {status} — {nerr} errors, {nwrn} warnings")
            for e in ir.extra.get("_v2_errors", []):
                print(f"    ✗ [{e['check']}] {e['message']}")
            for w in ir.extra.get("_v2_warnings", []):
                print(f"    ⚠ [{w['check']}] {w['message']}")
        if "_v3_ran" in ir.extra:
            if ir.extra["_v3_ran"]:
                v3s = "PASS" if ir.extra["_v3_passed"] else "FAIL"
                v3s += f" ({ir.extra.get('_v3_mode', 'import')})"
            else:
                v3s = "SKIPPED (Docker unavailable)"
            print(f"  V-3 container test:    {v3s}")

        run_status = ir.extra.get("_status")
        if run_status is not None:
            print(f"\n  Run status: {run_status.upper()}")
            for key in ir.extra.get("_unresolved", []):
                print(f"    ✗ unresolved: {key}")
            if run_status in _FAILING_STATUSES:
                sys.exit(1)


if __name__ == "__main__":
    main()
