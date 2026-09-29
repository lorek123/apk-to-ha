# SPDX-License-Identifier: MIT
"""Compare a CaptureSession against the static ProtocolIR and produce patches.

The reconciler does not mutate the IR directly — it returns a ReconciliationReport
that the pipeline applies via ir.model_copy().
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from ..extraction.signing_emitter import build as build_signing_ctx
from ..ir.models import (
    Direction,
    Endpoint,
    ProtocolIR,
    SigningComponent,
    SigningTrace,
)
from .capture_model import CaptureSession, HmacCapture

_LOGGER = logging.getLogger(__name__)


@dataclass
class SigningVerification:
    """Result of verifying the P2-6 signer against a live HMAC capture."""

    verified: bool
    corrected: bool = False
    corrected_trace: SigningTrace | None = None
    detail: str = ""


@dataclass
class ReconciliationReport:
    """Full output of one oracle reconciliation pass."""

    # Signing
    signing: SigningVerification | None = None
    # IR patches
    new_commands: list[str] = field(default_factory=list)
    removed_commands: list[str] = field(default_factory=list)
    field_corrections: list[dict[str, Any]] = field(default_factory=list)  # {cmd, old, new}
    discovery_port_correction: int | None = None
    auth_cmd_correction: str | None = None
    # Patched IR (None if no changes needed)
    patched_ir: ProtocolIR | None = None
    # Confidence delta applied to all signing traces
    confidence_boost: float = 0.0
    capture_summary: dict[str, Any] = field(default_factory=dict)


def reconcile(
    session: CaptureSession,
    ir: ProtocolIR,
) -> ReconciliationReport:
    """Diff *session* against *ir* and return a ReconciliationReport."""
    report = ReconciliationReport()
    report.capture_summary = {
        "hmac_calls": len(session.hmac_calls),
        "http_calls": len(session.http_calls),
        "ws_frames": len(session.ws_frames),
    }

    if session.is_empty:
        _LOGGER.warning("reconciler: empty capture session — nothing to reconcile")
        return report

    # ── 1. Signing verification ────────────────────────────────────────────────
    if session.hmac_calls and ir.signing_traces:
        report.signing = _verify_signing(session.hmac_calls, ir.signing_traces)
        if report.signing.verified:
            report.confidence_boost = 0.15
        elif report.signing.corrected:
            report.confidence_boost = 0.1

    # ── 2. Command reconciliation ─────────────────────────────────────────────
    observed_cmds = _extract_commands_from_session(session)
    ir_cmds = {ep.cmd for ep in ir.commands + ir.events}

    for cmd in observed_cmds - ir_cmds:
        _LOGGER.info("reconciler: new command observed: %r", cmd)
        report.new_commands.append(cmd)

    # Don't remove IR commands just because they weren't observed in this run —
    # some commands are rarely triggered. Only flag as suspicious.

    # ── 3. Field-name corrections from HTTP/WS bodies ────────────────────────
    report.field_corrections = _field_corrections(session, ir)

    # ── 4. Discovery port correction from UDP ────────────────────────────────
    if session.udp_sends:
        observed_port = session.udp_sends[0].dst_port
        if ir.discovery.port and ir.discovery.port != observed_port:
            _LOGGER.info(
                "reconciler: discovery port corrected %d → %d",
                ir.discovery.port,
                observed_port,
            )
            report.discovery_port_correction = observed_port

    # ── 5. Auth cmd correction from WS first-frame ───────────────────────────
    first_send = next((f for f in session.ws_frames if f.direction == "send"), None)
    if first_send:
        try:
            data = json.loads(first_send.frame)
            observed_auth = data.get("cmd")
            if observed_auth and observed_auth != ir.auth.handshake_cmd:
                _LOGGER.info(
                    "reconciler: auth_cmd corrected %r → %r",
                    ir.auth.handshake_cmd,
                    observed_auth,
                )
                report.auth_cmd_correction = observed_auth
        except json.JSONDecodeError, AttributeError:
            pass

    # ── 6. Build patched IR if anything changed ───────────────────────────────
    report.patched_ir = _apply_patches(ir, report)
    return report


# ── signing verification ──────────────────────────────────────────────────────


def _verify_signing(
    hmac_calls: list[HmacCapture],
    traces: list[SigningTrace],
) -> SigningVerification:
    best_trace = max(traces, key=lambda t: t.confidence)
    signing_ctx = build_signing_ctx(traces)
    if not signing_ctx.get("has_signing"):
        return SigningVerification(verified=False, detail="no signing context available")

    for capture in hmac_calls:
        if not capture.input_hex or not capture.key_hex:
            continue

        # Rebuild what P2-6 would produce with the captured key + input
        key_bytes = bytes.fromhex(capture.key_hex)
        input_bytes = bytes.fromhex(capture.input_hex)

        digest_name = signing_ctx.get("signing_digest", "sha256")
        digest_func = getattr(hashlib, digest_name, hashlib.sha256)

        computed = base64.b64encode(hmac.new(key_bytes, input_bytes, digest_func).digest()).decode()
        actual_b64 = base64.b64encode(bytes.fromhex(capture.output_hex)).decode()

        if computed == actual_b64:
            _LOGGER.info("reconciler: signing VERIFIED (algorithm=%s)", capture.algorithm)
            return SigningVerification(verified=True, detail=f"algorithm={capture.algorithm}")

        # Try to decode the input bytes as UTF-8 and attempt component re-ordering
        corrected = _attempt_signing_correction(
            input_bytes, key_bytes, capture, best_trace, digest_func
        )
        if corrected:
            return SigningVerification(
                verified=False,
                corrected=True,
                corrected_trace=corrected,
                detail="component order corrected from live capture",
            )

    return SigningVerification(verified=False, detail="HMAC output mismatch — needs manual review")


def _attempt_signing_correction(
    input_bytes: bytes,
    key_bytes: bytes,
    capture: HmacCapture,
    trace: SigningTrace,
    digest_func: Any,
) -> SigningTrace | None:
    """Try to decode the captured input and reconstruct the correct component order."""
    try:
        input_str = input_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    # Identify likely separator (most common: \n, empty string, &)
    separators = ["\n", "", "&", "|"]
    non_literal_comps = [c for c in trace.components if c.kind != "literal"]

    for sep in separators:
        # Try splitting by this separator
        parts = input_str.split(sep) if sep else [input_str]
        if len(parts) == len(non_literal_comps):
            # Found a plausible splitting — build a corrected trace
            new_components: list[SigningComponent] = []
            for i, (part, comp) in enumerate(zip(parts, non_literal_comps)):
                new_components.append(
                    SigningComponent(
                        kind=comp.kind,
                        variable_name=comp.variable_name,
                        confidence=0.9,
                    )
                )
                if sep and i < len(parts) - 1:
                    new_components.append(
                        SigningComponent(
                            kind="literal",
                            variable_name="",
                            value=sep,
                            confidence=1.0,
                        )
                    )
            return SigningTrace(
                algorithm=trace.algorithm,
                components=new_components,
                key_source=trace.key_source,
                source_method=trace.source_method,
                confidence=0.88,
                unresolved=[],
            )
    return None


# ── command / field extraction ────────────────────────────────────────────────


def _extract_commands_from_session(session: CaptureSession) -> set[str]:
    """Extract command names from WS frames and HTTP paths."""
    cmds: set[str] = set()

    for frame in session.ws_sends():
        try:
            data = json.loads(frame.frame)
            cmd = data.get("cmd")
            if cmd and isinstance(cmd, str):
                cmds.add(cmd)
        except json.JSONDecodeError, AttributeError:
            pass

    for call in session.http_calls:
        # Extract last path segment as a candidate command name
        path = call.url.split("?")[0].rstrip("/")
        if "/" in path:
            segment = path.rsplit("/", 1)[-1]
            if segment and not segment.isdigit():
                cmds.add(segment)

    return cmds


def _field_corrections(session: CaptureSession, ir: ProtocolIR) -> list[dict[str, Any]]:
    """Find field name mismatches between observed JSON and IR field definitions."""
    corrections: list[dict[str, Any]] = []
    observed_bodies: list[dict[str, Any]] = []

    for frame in session.ws_sends():
        try:
            observed_bodies.append(json.loads(frame.frame))
        except json.JSONDecodeError, AttributeError:
            pass

    for call in session.http_calls:
        if call.request_body:
            try:
                observed_bodies.append(json.loads(call.request_body))
            except json.JSONDecodeError, AttributeError:
                pass

    for body in observed_bodies:
        cmd = body.get("cmd")
        if not cmd:
            continue
        for ep in ir.commands:
            if ep.cmd != cmd:
                continue
            for field in ep.request_fields:
                observed_key = field.serialized_name or field.name
                if observed_key not in body and field.name in body:
                    corrections.append(
                        {
                            "cmd": cmd,
                            "field": field.name,
                            "old_serialized": observed_key,
                            "new_serialized": field.name,
                        }
                    )

    return corrections


# ── IR patching ────────────────────────────────────────────────────────────────


def _apply_patches(ir: ProtocolIR, report: ReconciliationReport) -> ProtocolIR | None:
    """Return a patched IR copy, or None if nothing changed."""
    updates: dict[str, Any] = {}
    changed = False

    # Boost signing trace confidence
    if report.confidence_boost > 0 and ir.signing_traces:
        boosted = [
            t.model_copy(update={"confidence": min(1.0, t.confidence + report.confidence_boost)})
            for t in ir.signing_traces
        ]
        if report.signing and report.signing.corrected_trace:
            boosted = [report.signing.corrected_trace] + boosted[1:]
        updates["signing_traces"] = boosted
        changed = True

    # Add new commands
    if report.new_commands:
        new_eps = [
            Endpoint(
                cmd=cmd,
                transport=ir.transport.type,
                direction=Direction.TO_DEVICE,
                confidence=0.6,
                description="Observed in dynamic capture — not in static IR",
            )
            for cmd in report.new_commands
        ]
        updates["commands"] = ir.commands + new_eps
        changed = True

    # Discovery port
    if report.discovery_port_correction:
        updates["discovery"] = ir.discovery.model_copy(
            update={"port": report.discovery_port_correction}
        )
        changed = True

    # Auth cmd
    if report.auth_cmd_correction:
        updates["auth"] = ir.auth.model_copy(update={"handshake_cmd": report.auth_cmd_correction})
        changed = True

    if not changed:
        return None

    return ir.model_copy(update=updates)
