# SPDX-License-Identifier: MIT
"""Orchestrates P1 → P-2.5 → P3 → snapshot for one APK."""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from pathlib import Path

import aiohttp

from .duplicate_check import checker as dup_checker
from .extraction.protocol_scanner import ProtocolScanner
from .ingestion import classifier, decompiler, manifest_parser
from .ir.models import Framework, ProtocolIR
from .snapshot import harness as snapshot_harness

_LOGGER = logging.getLogger(__name__)

_RUNS_DIR = Path(__file__).parents[2] / "runs"
_CACHE_DIR = Path(__file__).parents[2] / ".cache" / "jadx"


async def analyze(apk_path: Path, apk_id: str | None = None) -> ProtocolIR:
    """Run the full extraction pipeline on one APK. Returns the populated IR."""
    run_id = str(uuid.uuid4())[:8]
    apk_id = apk_id or apk_path.stem.lower().replace(" ", "_")
    log_entries: list[dict] = []

    def log(phase: str, step: str, level: str, message: str, **ctx) -> None:  # type: ignore[no-untyped-def]
        entry = {
            "run_id": run_id,
            "phase": phase,
            "step": step,
            "level": level,
            "message": message,
            "ts": time.time(),
            **ctx,
        }
        log_entries.append(entry)
        getattr(_LOGGER, level.lower(), _LOGGER.info)(message)

    log("P1", "start", "INFO", f"Analyzing {apk_path.name}", apk_id=apk_id)

    # ── P1: decompile ──────────────────────────────────────────────────────────
    out_dir = _CACHE_DIR / apk_id
    t0 = time.time()
    await decompiler.decompile(apk_path, out_dir)
    log("P1", "decompile", "INFO", "Decompilation complete", duration_ms=int((time.time() - t0) * 1000))

    # ── P1-4: parse manifest ───────────────────────────────────────────────────
    manifest = manifest_parser.parse(out_dir)
    log("P1", "manifest", "INFO", f"Package: {manifest.package_name}", permissions=len(manifest.permissions))

    # ── P1-2: Tuya check ──────────────────────────────────────────────────────
    if classifier.check_tuya(out_dir, manifest.package_name):
        log("P1", "tuya_check", "WARNING", "Tuya SDK detected — use tinytuya instead")
        raise TuyaDetectedError(manifest.package_name)

    # ── P1-3: classify framework ──────────────────────────────────────────────
    framework = classifier.classify(out_dir)
    log("P1", "classify", "INFO", f"Framework: {framework.value}")

    if framework != Framework.NATIVE:
        log("P1", "classify", "WARNING", f"{framework.value} path not implemented in M1 — extraction may be incomplete")

    # ── P2: protocol extraction ────────────────────────────────────────────────
    scanner = ProtocolScanner(out_dir)
    transport, discovery, auth, state, commands, events = scanner.scan(manifest.package_name)
    log("P2", "scan", "INFO",
        f"Extracted {len(commands)} commands, {len(events)} events",
        transport=transport.type.value,
        discovery=discovery.type.value,
    )

    # ── P-2.5: duplicate check ─────────────────────────────────────────────────
    async with aiohttp.ClientSession() as session:
        dup_result = await dup_checker.check(manifest.package_name, session)
    log("P2.5", "dup_check", "INFO",
        f"Duplicate check: found={dup_result.found}, coverage={dup_result.coverage_estimate}")

    if dup_result.found and dup_result.coverage_estimate == "full":
        log("P2.5", "dup_check", "WARNING",
            f"Full coverage found at {dup_result.location}/{dup_result.name} — skipping generation")

    # ── P3-1: assemble IR ─────────────────────────────────────────────────────
    ir = ProtocolIR(
        apk_path=str(apk_path),
        package_name=manifest.package_name,
        app_name=apk_path.stem,
        version_name=manifest.version_name,
        framework=framework,
        transport=transport,
        discovery=discovery,
        auth=auth,
        state=state,
        commands=commands,
        events=events,
        duplicate_check=dup_result,
        raw_permissions=manifest.permissions,
    )

    # ── F-2a: save snapshot ────────────────────────────────────────────────────
    snap_dir = snapshot_harness.write(apk_id, ir, out_dir)
    log("F2a", "snapshot", "INFO", f"Snapshot saved to {snap_dir}")

    # ── write run log ──────────────────────────────────────────────────────────
    run_dir = _RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    with (run_dir / "log.jsonl").open("w") as fh:
        for entry in log_entries:
            fh.write(json.dumps(entry) + "\n")

    log("pipeline", "done", "INFO", "Pipeline complete", run_id=run_id)
    return ir


class TuyaDetectedError(Exception):
    """Raised when the APK contains the Tuya SDK — use tinytuya instead."""
