#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""F-1 smoke test — emit and validate a HACS integration from the committed IR snapshot.

Uses fixtures/snapshots/bullb_r2d2/ir.json (no APK or JADX required).
Verifies required files exist, all JSON is valid, and ruff passes.

Exit 0 on pass, 1 on failure.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).parents[1]

# ── colour helpers ────────────────────────────────────────────────────────────


def _ok(msg: str) -> None:
    print(f"\033[1;32m[ok]\033[0m    {msg}")


def _fail(msg: str) -> None:
    print(f"\033[1;31m[FAIL]\033[0m  {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"\033[1;34m[smoke]\033[0m {msg}")


# ── checks ────────────────────────────────────────────────────────────────────

_REQUIRED_FILES = [
    "manifest.json",
    "__init__.py",
    "const.py",
    "config_flow.py",
    "coordinator.py",
    "entity_base.py",
    "strings.json",
    "translations/en.json",
]

_REQUIRED_JSON_KEYS = {
    "manifest.json": ["domain", "name", "version", "requirements"],
    "strings.json": ["config"],
    "translations/en.json": ["config"],
}

_MANIFEST_REQUIRED = {
    "iot_class",
    "homeassistant",
    "integration_type",
}


def check_files(domain_dir: Path) -> list[str]:
    errors: list[str] = []
    for rel in _REQUIRED_FILES:
        p = domain_dir / rel
        if not p.exists():
            errors.append(f"missing file: {rel}")
        else:
            _ok(f"{rel}")
    return errors


def check_json_valid(domain_dir: Path) -> list[str]:
    errors: list[str] = []
    for p in domain_dir.rglob("*.json"):
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON in {p.relative_to(domain_dir)}: {exc}")
            continue
        rel = str(p.relative_to(domain_dir))
        for key in _REQUIRED_JSON_KEYS.get(rel, []):
            if key not in data:
                errors.append(f"{rel}: missing required key '{key}'")
    return errors


def check_manifest(domain_dir: Path) -> list[str]:
    errors: list[str] = []
    manifest = json.loads((domain_dir / "manifest.json").read_text())
    for key in _MANIFEST_REQUIRED:
        if key not in manifest:
            errors.append(f"manifest.json: missing required field '{key}'")
    if not isinstance(manifest.get("requirements"), list):
        errors.append("manifest.json: 'requirements' must be a list")
    return errors


def check_spdx(domain_dir: Path) -> list[str]:
    errors: list[str] = []
    for p in domain_dir.rglob("*.py"):
        first = p.read_text(errors="replace").splitlines()
        if not first or "SPDX-License-Identifier: MIT" not in first[0]:
            errors.append(f"missing SPDX header: {p.relative_to(domain_dir)}")
    return errors


def check_entity_names(domain_dir: Path) -> list[str]:
    """translations/en.json should have entity section when platforms are present."""
    errors: list[str] = []
    # Check via which platform files exist
    platform_files = {
        "sensor": "sensor.py",
        "switch": "switch.py",
        "binary_sensor": "binary_sensor.py",
        "button": "button.py",
    }
    en = json.loads((domain_dir / "translations" / "en.json").read_text())
    for platform, fname in platform_files.items():
        if (domain_dir / fname).exists():
            entity_sec = en.get("entity", {})
            if platform not in entity_sec:
                errors.append(
                    f"translations/en.json: missing entity.{platform} section "
                    f"(Gold rule) while {fname} exists"
                )
    return errors


def check_ruff(domain_dir: Path) -> list[str]:
    errors: list[str] = []
    try:
        result = subprocess.run(
            ["ruff", "check", str(domain_dir)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            for line in result.stdout.strip().splitlines()[:5]:
                errors.append(f"ruff: {line}")
    except FileNotFoundError:
        _info("ruff not found — skipping lint check")
    return errors


# ── main ──────────────────────────────────────────────────────────────────────


def main(verbose: bool = False) -> int:
    sys.path.insert(0, str(_REPO / "src"))

    from engine.emitters import context as ctx_mod
    from engine.emitters import hacs_emitter, sdk_emitter
    from engine.ir.models import ProtocolIR

    snapshot = _REPO / "fixtures" / "snapshots" / "bullb_r2d2" / "ir.json"
    if not snapshot.exists():
        _fail(f"Snapshot not found: {snapshot}")
        _fail("Run `uv run python scripts/download_fixtures.py` to populate fixtures first.")
        return 1

    _info(f"Loading IR snapshot from {snapshot.relative_to(_REPO)}")
    ir = ProtocolIR.model_validate_json(snapshot.read_text())
    _ok(f"IR loaded: {ir.package_name} ({ir.framework.value})")
    _ok(
        f"  {len(ir.commands)} commands, {len(ir.events)} events, "
        f"transport={ir.transport.type.value}"
    )

    with tempfile.TemporaryDirectory(prefix="hacs_smoke_") as tmp:
        out = Path(tmp)
        _info("Building template context...")
        ctx = ctx_mod.build(ir)
        _ok(f"  platforms: {ctx['platforms']}")
        _ok(f"  domain:    {ctx['domain']}")
        _ok(f"  has_ble:   {ctx['has_ble']}")

        _info("Emitting HACS integration...")
        domain_dir = hacs_emitter.emit(ctx, out)
        _ok(f"  emitted to {domain_dir.relative_to(out)}")

        _info("Emitting SDK package...")
        sdk_dir = sdk_emitter.emit(ctx, out)
        _ok(f"  emitted to {sdk_dir.relative_to(out)}")

        _info("Running checks...")
        all_errors: list[str] = []

        all_errors += check_files(domain_dir)
        all_errors += check_json_valid(domain_dir)
        all_errors += check_manifest(domain_dir)
        all_errors += check_spdx(domain_dir)
        all_errors += check_entity_names(domain_dir)
        all_errors += check_ruff(domain_dir)

        if verbose:
            _info("Domain dir contents:")
            for p in sorted(domain_dir.rglob("*")):
                if p.is_file():
                    print(f"    {p.relative_to(domain_dir)}")

    if all_errors:
        _fail(f"{len(all_errors)} check(s) failed:")
        for e in all_errors:
            _fail(f"  • {e}")
        return 1

    _ok("Smoke test passed — HACS integration is valid.")
    return 0


if __name__ == "__main__":
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    sys.exit(main(verbose))
