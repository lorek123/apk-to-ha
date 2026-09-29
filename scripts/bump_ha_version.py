#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bump the HA Core version pin in config/ha_target.toml.

Updates ha_core_version, ha_image_tag, anchors.ref,
generated_minimum_required (set to <major>.<minor>.0 for the
compatibility window) and sandbox.phcc_version (the
pytest-homeassistant-custom-component release pinning that exact HA
version, looked up on PyPI).

Usage:  python scripts/bump_ha_version.py 2026.6.0
        make ha-bump NEW=2026.6.0
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

_TARGET = Path(__file__).parents[1] / "config" / "ha_target.toml"
_PHCC_PYPI = "https://pypi.org/pypi/pytest-homeassistant-custom-component"
_PHCC_SCAN = 60  # newest releases to check; phcc ships one per HA release/beta


def _pypi_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 — fixed https URL
        data: dict[str, Any] = json.load(resp)
    return data


def find_phcc_version(ha_ver: str) -> str:
    """Return the phcc release whose requirements pin ``homeassistant==ha_ver``."""
    releases = _pypi_json(f"{_PHCC_PYPI}/json")["releases"]
    newest = sorted(
        (v for v, files in releases.items() if files),
        key=lambda v: releases[v][0]["upload_time"],
        reverse=True,
    )
    for version in newest[:_PHCC_SCAN]:
        info = _pypi_json(f"{_PHCC_PYPI}/{version}/json")["info"]
        if f"homeassistant=={ha_ver}" in (info.get("requires_dist") or []):
            return str(version)
    raise LookupError(f"no pytest-homeassistant-custom-component release pins {ha_ver}")


def bump(new_ver: str, target: Path = _TARGET, phcc_version: str | None = None) -> None:
    new_ver = new_ver.lstrip("v")  # tolerate "v2026.6.0"
    parts = new_ver.split(".")
    if len(parts) < 2:
        print(f"ERROR: version must be YYYY.MM[.PATCH], got {new_ver!r}", file=sys.stderr)
        sys.exit(1)

    min_required = f"{parts[0]}.{parts[1]}.0"

    content = target.read_text()

    def _replace(key: str, val: str, text: str) -> str:
        return re.sub(
            rf'^({re.escape(key)}\s*=\s*)"[^"]+"',
            rf'\1"{val}"',
            text,
            flags=re.MULTILINE,
        )

    content = _replace("ha_core_version", new_ver, content)
    content = _replace("ha_image_tag", new_ver, content)
    content = _replace("ref", new_ver, content)
    content = _replace("generated_minimum_required", min_required, content)
    if phcc_version is not None:
        content = _replace("phcc_version", phcc_version, content)

    target.write_text(content)
    print(f"Bumped {target} → {new_ver} (min_required={min_required})")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    version = sys.argv[1].lstrip("v")
    bump(version, phcc_version=find_phcc_version(version))
