# SPDX-License-Identifier: MIT
"""CLI: python -m engine analyze <apk_path> [--id <apk_id>]"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from .pipeline import TuyaDetectedError, analyze

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


def main() -> None:
    parser = argparse.ArgumentParser(prog="engine", description="APK → HA integration pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("analyze", help="Run P1→P-2.5→P3→snapshot on an APK")
    p.add_argument("apk", type=Path, help="Path to the .apk file")
    p.add_argument("--id", dest="apk_id", default=None, help="Override fixture ID (default: apk stem)")
    p.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.cmd == "analyze":
        if not args.apk.exists():
            print(f"ERROR: {args.apk} does not exist", file=sys.stderr)
            sys.exit(1)

        try:
            ir = asyncio.run(analyze(args.apk, apk_id=args.apk_id))
        except TuyaDetectedError as exc:
            print(f"\n⚠  Tuya SDK detected in {exc}.")
            print("   This device is already supported via tinytuya / HA Core 'tuya' integration.")
            print("   Pipeline halted — no integration generated.")
            sys.exit(2)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            if args.verbose:
                raise
            sys.exit(1)

        print(f"\n✓ Extraction complete")
        print(f"  Package:    {ir.package_name}")
        print(f"  Framework:  {ir.framework.value}")
        print(f"  Transport:  {ir.transport.type.value}  port={ir.transport.port}")
        print(f"  Discovery:  {ir.discovery.type.value}  port={ir.discovery.port}")
        print(f"  Auth:       {ir.auth.type.value}  ({ir.auth.handshake_cmd or 'n/a'})")
        print(f"  Commands:   {len(ir.commands)}")
        print(f"  Events:     {len(ir.events)}")
        print(f"  State fields: {len(ir.state.fields)}")
        if ir.duplicate_check and ir.duplicate_check.found:
            print(f"  ⚠  Duplicate: {ir.duplicate_check.location}/{ir.duplicate_check.name}"
                  f" ({ir.duplicate_check.coverage_estimate} coverage)")
        print(f"\n  Snapshot:   fixtures/snapshots/{args.apk_id or args.apk.stem.lower()}/")


if __name__ == "__main__":
    main()
