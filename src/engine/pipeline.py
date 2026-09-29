# SPDX-License-Identifier: MIT
"""Orchestrates P1 → P-2.5 → P3 → snapshot for one APK."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

import aiohttp

from .duplicate_check import checker as dup_checker
from .dynamic import oracle as dynamic_oracle
from .emitters import context as emitter_context
from .emitters import hacs_emitter, sdk_emitter
from .extraction import entity_classifier
from .extraction.ble_scanner import BLEScanner
from .extraction.crypto_scanner import scan as crypto_scan
from .extraction.java_code_graph import JavaCodeGraph
from .extraction.protocol_scanner import ProtocolScanner
from .extraction.rn_scanner import RNScanner
from .extraction.signing_tracer import LLM_THRESHOLD
from .extraction.signing_tracer import escalate as signing_escalate
from .extraction.signing_tracer import trace as signing_trace
from .extraction.strings_scanner import scan as strings_scan
from .ingestion import classifier, decompiler, manifest_parser
from .ingestion import play_store as play_store_fetcher
from .ir.models import Framework, ProtocolIR
from .snapshot import harness as snapshot_harness
from .validation import container_test, fix_router, log_analyzer, quality_checker, ruff_check
from .validation import hassfest as hassfest_validator

_LOGGER = logging.getLogger(__name__)

_RUNS_DIR = Path(__file__).parents[2] / "runs"
_CACHE_DIR = Path(__file__).parents[2] / ".cache" / "jadx"
_OUTPUT_DIR = Path(__file__).parents[2] / "sdk_output"


async def analyze(apk_path: Path, apk_id: str | None = None, emit: bool = True) -> ProtocolIR:
    """Run the full extraction pipeline on one APK. Returns the populated IR."""
    run_id = str(uuid.uuid4())[:8]
    apk_id = apk_id or apk_path.stem.lower().replace(" ", "_")
    log_entries: list[dict[str, Any]] = []

    def log(phase: str, step: str, level: str, message: str, **ctx: object) -> None:
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
    log(
        "P1",
        "decompile",
        "INFO",
        "Decompilation complete",
        duration_ms=int((time.time() - t0) * 1000),
    )

    # ── P1-4: parse manifest ───────────────────────────────────────────────────
    manifest = manifest_parser.parse(out_dir)
    log(
        "P1",
        "manifest",
        "INFO",
        f"Package: {manifest.package_name}",
        permissions=len(manifest.permissions),
    )

    # ── P1-2: Tuya check ──────────────────────────────────────────────────────
    if classifier.check_tuya(out_dir, manifest.package_name):
        log("P1", "tuya_check", "WARNING", "Tuya SDK detected — use tinytuya instead")
        raise TuyaDetectedError(manifest.package_name)

    # ── P1-3: classify framework ──────────────────────────────────────────────
    framework = classifier.classify(out_dir)
    log("P1", "classify", "INFO", f"Framework: {framework.value}")

    if framework == Framework.FLUTTER:
        log(
            "P1",
            "classify",
            "WARNING",
            "Flutter path (P1-5) not yet implemented — extraction will be incomplete",
        )

    # ── P2: protocol extraction ────────────────────────────────────────────────
    extra_ctx: dict[str, Any] = {}
    if framework == Framework.REACT_NATIVE:
        rn = RNScanner(out_dir)
        transport, discovery, auth, state, commands, events = rn.scan(manifest.package_name)
    else:
        scanner = ProtocolScanner(out_dir)
        transport, discovery, auth, state, commands, events = scanner.scan(manifest.package_name)
        extra_ctx = scanner.extra

        # ── P2-8: BLE endpoint augmentation ──────────────────────────────────
        ble = BLEScanner(out_dir)
        ble_transport, _, _, _, ble_commands, ble_events = ble.scan(manifest.package_name)
        if ble_commands or ble_events:
            commands = commands + ble_commands
            events = events + ble_events
            extra_ctx = {**extra_ctx, **ble.extra}
            if not (transport.type.value != "ble") or not commands:
                transport = ble_transport
            log(
                "P2",
                "ble_scan",
                "INFO",
                f"BLE: {len(ble_commands)} commands, {len(ble_events)} events",
                service_uuids=ble.extra.get("ble_service_uuids", []),
            )

    log(
        "P2",
        "scan",
        "INFO",
        f"Extracted {len(commands)} commands, {len(events)} events",
        transport=transport.type.value,
        discovery=discovery.type.value,
    )

    # ── P-2.5: duplicate check + Play Store metadata (parallel network calls) ───
    _ble_uuids = extra_ctx.get("ble_service_uuids") or []
    async with aiohttp.ClientSession() as session:
        dup_result, ps_info = await asyncio.gather(
            dup_checker.check(
                manifest.package_name,
                session,
                ble_service_uuids=_ble_uuids or None,
            ),
            play_store_fetcher.fetch(manifest.package_name),
        )
    log(
        "P2.5",
        "dup_check",
        "INFO",
        f"Duplicate check: found={dup_result.found}, coverage={dup_result.coverage_estimate}",
    )
    if ps_info:
        log(
            "P2.5",
            "play_store",
            "INFO",
            f"Play Store: {ps_info.title!r} ({ps_info.category}) by {ps_info.developer}",
        )
    else:
        log("P2.5", "play_store", "INFO", "Play Store: not found or unavailable")

    if dup_result.found and dup_result.coverage_estimate == "full":
        log(
            "P2.5",
            "dup_check",
            "WARNING",
            f"Full coverage found at {dup_result.location}/{dup_result.name} — stopping",
        )
        raise DuplicateFoundError(manifest.package_name, dup_result.name, dup_result.location)

    # ── P5-6: Android string resources ───────────────────────────────────────
    android_strings = strings_scan(out_dir)
    if android_strings:
        extra_ctx = {**extra_ctx, "android_strings": android_strings}
        log(
            "P5",
            "strings_scan",
            "INFO",
            f"Extracted {len(android_strings)} user-facing strings from strings.xml",
        )
    else:
        log("P5", "strings_scan", "DEBUG", "No strings.xml or no relevant strings found")

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
        play_store=ps_info,
        duplicate_check=dup_result,
        raw_permissions=manifest.permissions,
        extra=extra_ctx,
    )

    # ── P2-4: crypto API scan ─────────────────────────────────────────────────
    crypto_usages = crypto_scan(out_dir)
    log(
        "P2",
        "crypto",
        "INFO",
        f"Crypto usages: {len(crypto_usages)}",
        algorithms=[u.algorithm for u in crypto_usages if u.confidence >= 0.7],
    )
    ir = ir.model_copy(update={"crypto": crypto_usages})

    # ── P2-5: signing-input tracer (static path) ──────────────────────────────
    t0 = time.time()
    code_graph = JavaCodeGraph.build(out_dir)
    log(
        "P2",
        "code_graph",
        "INFO",
        f"Call graph: {len(code_graph.method_sources)} methods indexed",
        duration_ms=int((time.time() - t0) * 1000),
    )
    traces = signing_trace(crypto_usages, out_dir, code_graph)
    high_conf = [t for t in traces if t.confidence >= LLM_THRESHOLD]
    needs_llm = [t for t in traces if t.confidence < LLM_THRESHOLD]
    log(
        "P2",
        "signing_tracer",
        "INFO",
        f"Signing traces: {len(traces)} total, {len(high_conf)} high-conf, "
        f"{len(needs_llm)} need LLM escalation",
    )
    for t in needs_llm:
        log(
            "P2",
            "signing_tracer",
            "WARNING",
            f"{t.source_method}: confidence={t.confidence:.2f} unresolved={t.unresolved}",
        )

    # ── F-4: LLM escalation for low-confidence traces ─────────────────────────
    if needs_llm:
        traces = await signing_escalate(traces, out_dir)
        still_low = [t for t in traces if t.confidence < LLM_THRESHOLD]
        log(
            "P2",
            "signing_escalate",
            "INFO",
            f"LLM escalation: {len(needs_llm) - len(still_low)}/{len(needs_llm)} resolved",
            remaining_low_conf=len(still_low),
        )

    ir = ir.model_copy(update={"signing_traces": traces})

    # ── P2-7: dynamic oracle (redroid + Frida) ────────────────────────────────
    oracle_report = await dynamic_oracle.run(apk_path, ir)
    if oracle_report.patched_ir is not None:
        ir = oracle_report.patched_ir
        log(
            "P2",
            "oracle",
            "INFO",
            f"Oracle patched IR: new_cmds={oracle_report.new_commands} "
            f"confidence_boost={oracle_report.confidence_boost:.2f}",
        )
    else:
        log(
            "P2",
            "oracle",
            "INFO",
            f"Oracle: skipped or no patches — "
            f"hmac={oracle_report.capture_summary.get('hmac_calls', 0)} "
            f"http={oracle_report.capture_summary.get('http_calls', 0)} "
            f"ws={oracle_report.capture_summary.get('ws_frames', 0)}",
        )
    if oracle_report.signing:
        sv = oracle_report.signing
        level = "INFO" if sv.verified else "WARNING"
        log(
            "P2",
            "oracle",
            level,
            f"Signing: verified={sv.verified} corrected={sv.corrected} — {sv.detail}",
        )

    # ── P3-2: entity hint classification ─────────────────────────────────────
    ir = entity_classifier.classify(ir)
    log("P3", "entity_hints", "INFO", f"Entity hints: {_count_hints(ir)}")

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
        ir = ir.model_copy(
            update={"extra": {**ir.extra, "_sdk_dir": str(sdk_dir), "_hacs_dir": str(hacs_dir)}}
        )

        # ── V-1 / V-2 validation loop (max 3 iterations per §8) ──────────────
        _MAX_ITERATIONS = 3
        v1_hacs = v1_sdk = v2 = None
        for iteration in range(_MAX_ITERATIONS):
            v1_hacs = await ruff_check.check(hacs_dir)
            v1_sdk = await ruff_check.check(sdk_dir)
            v2 = await hassfest_validator.validate(hacs_dir)

            v1_errors = v1_hacs.error_count + v1_sdk.error_count
            v1_warnings = v1_hacs.warning_count + v1_sdk.warning_count
            log(
                "V1",
                "ruff",
                "INFO" if (v1_hacs.passed and v1_sdk.passed) else "WARNING",
                f"[iter {iteration}] ruff: {v1_errors} errors, {v1_warnings} warnings",
            )
            for f in v1_hacs.findings + v1_sdk.findings:
                log(
                    "V1",
                    "ruff",
                    "WARNING" if f.code.startswith("W") else "ERROR",
                    f"{Path(f.file).name}:{f.line} [{f.code}] {f.message}",
                )

            log(
                "V2",
                "hassfest",
                "INFO" if v2.passed else "WARNING",
                f"[iter {iteration}] hassfest ({v2.tier}): {'PASS' if v2.passed else 'FAIL'} "
                f"— {len(v2.errors)} errors, {len(v2.warnings)} warnings",
            )
            for finding in v2.findings:
                log(
                    "V2",
                    "hassfest",
                    finding.severity.upper(),
                    f"[{finding.check}] {finding.message}",
                )

            if v1_hacs.passed and v1_sdk.passed and v2.passed:
                break  # clean — no fixes needed

            fix = fix_router.route_and_apply(
                ruff_findings=v1_hacs.findings + v1_sdk.findings,
                hassfest_findings=v2.findings,
                ctx=ctx,
                integration_dir=hacs_dir,
            )
            log(
                "V5",
                "fix_router",
                "INFO",
                f"[iter {iteration}] applied={fix.applied} skipped={fix.skipped}",
            )
            for detail in fix.details:
                log("V5", "fix_router", "INFO", detail)

            if fix.applied == 0:
                log(
                    "V5",
                    "fix_router",
                    "WARNING",
                    "No deterministic fixes available — escalating to human review",
                )
                break

        assert v1_hacs is not None and v1_sdk is not None and v2 is not None

        # ── V-4: platinum quality rubric ─────────────────────────────────────
        v4 = quality_checker.check(hacs_dir)
        log(
            "V4",
            "quality",
            "INFO" if v4.passed else "WARNING",
            f"quality: {'PASS' if v4.passed else 'FAIL'} "
            f"— {len(v4.errors)} errors, {len(v4.warnings)} warnings",
        )
        for r in v4.failures:
            log(
                "V4", "quality", r.rule.severity.upper(), f"[{r.rule.id}] {r.rule.name}: {r.detail}"
            )

        # ── V-3: HA container import test ─────────────────────────────────────
        v3 = await container_test.run(ctx["domain"], run_out)
        if v3.ran:
            log(
                "V3",
                "container",
                "INFO" if v3.passed else "WARNING",
                f"container import: {'PASS' if v3.passed else 'FAIL'}",
            )
            if not v3.passed:
                log("V3", "container", "WARNING", v3.error or v3.output[:500])

        # ── V-7: HA log analysis ──────────────────────────────────────────────
        v7_findings = log_analyzer.analyze(v3.output if v3.ran else "")
        for lf in v7_findings:
            log("V7", "log_analyzer", lf.severity.upper(), f"[{lf.category}] {lf.message}")

        ir = ir.model_copy(
            update={
                "extra": {
                    **ir.extra,
                    "_v1_passed": v1_hacs.passed and v1_sdk.passed,
                    "_v1_errors": v1_hacs.error_count + v1_sdk.error_count,
                    "_v1_warnings": v1_hacs.warning_count + v1_sdk.warning_count,
                    "_v2_passed": v2.passed,
                    "_v2_tier": v2.tier,
                    "_v2_errors": [{"check": f.check, "message": f.message} for f in v2.errors],
                    "_v2_warnings": [{"check": f.check, "message": f.message} for f in v2.warnings],
                    "_v4_passed": v4.passed,
                    "_v4_errors": [
                        {"id": r.rule.id, "name": r.rule.name, "detail": r.detail}
                        for r in v4.errors
                    ],
                    "_v4_warnings": [
                        {"id": r.rule.id, "name": r.rule.name, "detail": r.detail}
                        for r in v4.warnings
                    ],
                    "_v3_ran": v3.ran,
                    "_v3_passed": v3.passed,
                    "_v7_findings": [
                        {"category": lf.category, "severity": lf.severity, "message": lf.message}
                        for lf in v7_findings
                    ],
                }
            }
        )

    # ── V-6: write run state ──────────────────────────────────────────────────
    run_dir = _RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Structured event log
    with (run_dir / "log.jsonl").open("w") as fh:
        for entry in log_entries:
            fh.write(json.dumps(entry) + "\n")

    # Full IR snapshot — enables offline replay and debugging
    (run_dir / "ir.json").write_text(ir.model_dump_json(indent=2))

    # Output hash — detects regressions across runs for the same APK
    output_hash: str | None = None
    if emit:
        hacs_path = Path(ir.extra.get("_hacs_dir", ""))
        if hacs_path.exists():
            h = hashlib.sha256()
            for fp in sorted(hacs_path.rglob("*")):
                if fp.is_file():
                    h.update(fp.name.encode())
                    h.update(fp.read_bytes())
            output_hash = h.hexdigest()[:16]

    # Human-readable run summary
    summary = {
        "run_id": run_id,
        "apk": str(apk_path),
        "package_name": ir.package_name,
        "app_name": ir.app_name,
        "ts": time.time(),
        "emit": emit,
        "v1_passed": ir.extra.get("_v1_passed"),
        "v2_passed": ir.extra.get("_v2_passed"),
        "v2_tier": ir.extra.get("_v2_tier"),
        "v3_ran": ir.extra.get("_v3_ran"),
        "v3_passed": ir.extra.get("_v3_passed"),
        "v4_passed": ir.extra.get("_v4_passed"),
        "v7_findings": len(ir.extra.get("_v7_findings", [])),
        "crypto_usages": len(ir.crypto),
        "output_hash": output_hash,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    log("pipeline", "done", "INFO", "Pipeline complete", run_id=run_id, output_hash=output_hash)
    return ir


class TuyaDetectedError(Exception):
    """Raised when the APK contains the Tuya SDK — use tinytuya instead."""


class DuplicateFoundError(Exception):
    """Raised when an existing integration with full coverage is found."""

    def __init__(
        self, package_name: str, integration_name: str | None, location: str | None
    ) -> None:
        super().__init__(f"{package_name} already covered by {location}/{integration_name}")
        self.package_name = package_name
        self.integration_name = integration_name
        self.location = location


def _count_hints(ir: ProtocolIR) -> str:
    from collections import Counter

    c: Counter[str] = Counter()
    for ep in ir.commands + ir.events:
        c[ep.entity_hint.value if ep.entity_hint else "none"] += 1
    return ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
