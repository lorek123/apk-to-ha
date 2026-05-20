#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Download APK fixtures listed in fixtures/sources.yaml.

Skips entries with placeholder URLs (containing 'example.invalid').
Skips entries where the local file already exists.

Usage:  uv run python scripts/download_fixtures.py
        make fixtures
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml not installed — run: uv pip install pyyaml", file=sys.stderr)
    sys.exit(1)

_ROOT = Path(__file__).parents[1]
_SOURCES = _ROOT / "fixtures" / "sources.yaml"
_CACHE = _ROOT / "fixtures" / "_cache"


def main() -> None:
    _CACHE.mkdir(parents=True, exist_ok=True)

    with open(_SOURCES) as fh:
        data = yaml.safe_load(fh)

    downloaded = skipped = errors = 0
    for apk in data.get("apks", []):
        apk_id = apk.get("id", "unknown")
        apk_url = apk.get("apk_url", "")

        if "example.invalid" in apk_url or not apk_url:
            print(f"  skip  {apk_id}: placeholder URL — download manually to fixtures/_cache/")
            skipped += 1
            continue

        local = apk.get("local_path")
        out_path = _ROOT / local if local else _CACHE / f"{apk_id}.apk"

        if out_path.exists():
            print(f"  skip  {apk_id}: already at {out_path.relative_to(_ROOT)}")
            skipped += 1
            continue

        out_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"  fetch {apk_id}: {apk_url}")
        try:
            urllib.request.urlretrieve(apk_url, out_path)
            size_mb = out_path.stat().st_size / 1_048_576
            print(f"        → {out_path.relative_to(_ROOT)} ({size_mb:.1f} MB)")
            downloaded += 1
        except Exception as exc:
            print(f"  ERROR {apk_id}: {exc}", file=sys.stderr)
            errors += 1

    print(f"\nDone: {downloaded} downloaded, {skipped} skipped, {errors} errors.")
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
