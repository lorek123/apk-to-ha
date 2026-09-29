# SPDX-License-Identifier: MIT
"""F-2a — Snapshot harness.

Writes a committable snapshot bundle to fixtures/snapshots/{apk_id}/:
  ir.json           — full ProtocolIR
  manifest.xml      — AndroidManifest.xml excerpt (no binary)
  classes.txt       — list of app-package class names

No APK binaries are written. All output is text/JSON.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

import yaml

from ..ir.models import ProtocolIR
from ..ir.openapi_emitter import emit as openapi_emit
from ..ir.openapi_validator import validate as openapi_validate

_LOGGER = logging.getLogger(__name__)

_SNAPSHOTS_DIR = Path(__file__).parents[3] / "fixtures" / "snapshots"


def write(apk_id: str, ir: ProtocolIR, apk_out_dir: Path) -> Path:
    """Write snapshot bundle, return the snapshot directory path."""
    snap_dir = _SNAPSHOTS_DIR / apk_id
    snap_dir.mkdir(parents=True, exist_ok=True)

    # ir.json
    (snap_dir / "ir.json").write_text(ir.model_dump_json(indent=2))

    # openapi.yaml (P3-2)
    openapi_doc = openapi_emit(ir)
    (snap_dir / "openapi.yaml").write_text(
        yaml.dump(openapi_doc, sort_keys=False, allow_unicode=True)
    )

    # openapi validation report (P3-3)
    validation = openapi_validate(openapi_doc)
    if not validation.passed:
        _LOGGER.warning("openapi: validation failed (%d errors)", validation.error_count)
        for err in validation.errors:
            _LOGGER.warning("openapi: %s", err)
    (snap_dir / "openapi_validation.json").write_text(
        __import__("json").dumps(
            {
                "passed": validation.passed,
                "errors": validation.errors,
                "warnings": validation.warnings,
            },
            indent=2,
        )
    )

    # manifest excerpt
    manifest_src = apk_out_dir / "resources" / "AndroidManifest.xml"
    if manifest_src.exists():
        shutil.copy(manifest_src, snap_dir / "manifest.xml")

    # class list (app package only)
    sources = apk_out_dir / "sources"
    pkg_path = sources / ir.package_name.replace(".", "/")
    if pkg_path.exists():
        classes = sorted(
            str(f.relative_to(sources)).replace("/", ".").removesuffix(".java")
            for f in pkg_path.rglob("*.java")
        )
        (snap_dir / "classes.txt").write_text("\n".join(classes) + "\n")

    _LOGGER.info("Snapshot written to %s", snap_dir)
    return snap_dir


def load(apk_id: str) -> ProtocolIR:
    """Load a previously saved snapshot."""
    ir_path = _SNAPSHOTS_DIR / apk_id / "ir.json"
    if not ir_path.exists():
        raise FileNotFoundError(f"No snapshot for {apk_id!r} at {ir_path}")
    return ProtocolIR.model_validate_json(ir_path.read_text())
