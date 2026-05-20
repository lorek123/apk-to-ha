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
from .emitters import context as emitter_context
from .emitters import hacs_emitter, sdk_emitter
from .extraction import entity_classifier
from .extraction.protocol_scanner import ProtocolScanner
from .ingestion import classifier, decompiler, manifest_parser
from .ir.models import Framework, ProtocolIR
from .snapshot import harness as snapshot_harness
from .validation import fix_router
from .validation import hassfest as hassfest_validator
from .validation import ruff_check, container_test

_LOGGER = logging.getLogger(__name__)

_RUNS_DIR = Path(__file__).parents[2] / "runs"
_CACHE_DIR = Path(__file__).parents[2] / ".cache" / "jadx"
_OUTPUT_DIR = Path(__file__).parents[2] / "sdk_output"


async def analyze(apk_path: Path, apk_id: str | None = None, emit: bool = True) -> ProtocolIR:
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
        extra=scanner.extra,
    )

    # ── P3-2: entity hint classification ─────────────────────────────────────
    ir = entity_classifier.classify(ir)
    log("P3", "entity_hints", "INFO",
        f"Entity hints: {_count_hints(ir)}")

    # ── F-2a: save snapshot ────────────────────────────────────────────────────
    snap_dir = snapshot_harness.write(apk_id, ir, out_dir)
    log("F2a", "snapshot", "INFO", f"Snapshot saved to {snap_dir}")

    # ── P4/P5: emit SDK + HACS integration ────────────────────────────────────
    if emit:
        ctx = emitter_context.build(ir)
        run_out = _OUTPUT_DIR / apk_id
        sdk_dir = sdk_emitter.emit(ctx, run_out)
        hacs_dir = hacs_emitter.emit(ctx, run_out)
        log("P4", "sdk_emit", "INFO", f"SDK emitted to {sdk_dir}")
        log("P5", "hacs_emit", "INFO", f"HACS integration emitted to {hacs_dir}")
        ir = ir.model_copy(update={"extra": {**ir.extra, "_sdk_dir": str(sdk_dir), "_hacs_dir": str(hacs_dir)}})

        # ── V-1 / V-2 validation loop (max 3 iterations per §8) ──────────────
        _MAX_ITERATIONS = 3
        v1_hacs = v1_sdk = v2 = None
        for iteration in range(_MAX_ITERATIONS):
            v1_hacs = await ruff_check.check(hacs_dir)
            v1_sdk = await ruff_check.check(sdk_dir)
            v2 = await hassfest_validator.validate(hacs_dir)

            v1_errors = v1_hacs.error_count + v1_sdk.error_count
            v1_warnings = v1_hacs.warning_count + v1_sdk.warning_count
            log("V1", "ruff", "INFO" if (v1_hacs.passed and v1_sdk.passed) else "WARNING",
                f"[iter {iteration}] ruff: {v1_errors} errors, {v1_warnings} warnings")
            for f in v1_hacs.findings + v1_sdk.findings:
                log("V1", "ruff", "WARNING" if f.code.startswith("W") else "ERROR",
                    f"{Path(f.file).name}:{f.line} [{f.code}] {f.message}")

            log("V2", "hassfest", "INFO" if v2.passed else "WARNING",
                f"[iter {iteration}] hassfest ({v2.tier}): {'PASS' if v2.passed else 'FAIL'} "
                f"— {len(v2.errors)} errors, {len(v2.warnings)} warnings")
            for finding in v2.findings:
                log("V2", "hassfest", finding.severity.upper(),
                    f"[{finding.check}] {finding.message}")

            if v1_hacs.passed and v1_sdk.passed and v2.passed:
                break  # clean — no fixes needed

            fix = fix_router.route_and_apply(
                ruff_findings=v1_hacs.findings + v1_sdk.findings,
                hassfest_findings=v2.findings,
                ctx=ctx,
                integration_dir=hacs_dir,
            )
            log("V5", "fix_router", "INFO",
                f"[iter {iteration}] applied={fix.applied} skipped={fix.skipped}")
            for detail in fix.details:
                log("V5", "fix_router", "INFO", detail)

            if fix.applied == 0:
                log("V5", "fix_router", "WARNING",
                    "No deterministic fixes available — escalating to human review")
                break

        assert v1_hacs is not None and v1_sdk is not None and v2 is not None

        # ── V-3: HA container import test ─────────────────────────────────────
        v3 = await container_test.run(ctx["domain"], run_out)
        if v3.ran:
            log("V3", "container", "INFO" if v3.passed else "WARNING",
                f"container import: {'PASS' if v3.passed else 'FAIL'}")
            if not v3.passed:
                log("V3", "container", "WARNING", v3.error or v3.output[:500])

        ir = ir.model_copy(update={"extra": {
            **ir.extra,
            "_v1_passed": v1_hacs.passed and v1_sdk.passed,
            "_v1_errors": v1_hacs.error_count + v1_sdk.error_count,
            "_v1_warnings": v1_hacs.warning_count + v1_sdk.warning_count,
            "_v2_passed": v2.passed,
            "_v2_tier": v2.tier,
            "_v2_errors": [{"check": f.check, "message": f.message} for f in v2.errors],
            "_v2_warnings": [{"check": f.check, "message": f.message} for f in v2.warnings],
            "_v3_ran": v3.ran,
            "_v3_passed": v3.passed,
        }})

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


def _count_hints(ir: ProtocolIR) -> str:
    from collections import Counter
    c: Counter = Counter()
    for ep in ir.commands + ir.events:
        c[ep.entity_hint.value if ep.entity_hint else "none"] += 1
    return ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
