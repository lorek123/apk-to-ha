#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bump the HA Core version pin in config/ha_target.toml.

Updates ha_core_version, ha_image_tag, anchors.ref, and
generated_minimum_required (set to <major>.<minor>.0 for the
compatibility window).

Usage:  python scripts/bump_ha_version.py 2026.6.0
        make ha-bump NEW=2026.6.0
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_TARGET = Path(__file__).parents[1] / "config" / "ha_target.toml"


def bump(new_ver: str, target: Path = _TARGET) -> None:
    new_ver = new_ver.lstrip("v")  # tolerate "v2026.6.0"
    parts = new_ver.split(".")
    if len(parts) < 2:
        print(f"ERROR: version must be YYYY.MM[.PATCH], got {new_ver!r}", file=sys.stderr)
        sys.exit(1)

    min_required = f"{parts[0]}.{parts[1]}.0"

    content = target.read_text()

    def _replace(key: str, val: str, text: str) -> str:
        return re.sub(
            rf'({re.escape(key)}\s*=\s*)"[^"]+"',
            rf'\1"{val}"',
            text,
        )

    content = _replace("ha_core_version", new_ver, content)
    content = _replace("ha_image_tag", new_ver, content)
    content = _replace("ref", new_ver, content)
    content = _replace("generated_minimum_required", min_required, content)

    target.write_text(content)
    print(f"Bumped {target} → {new_ver} (min_required={min_required})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    bump(sys.argv[1])
