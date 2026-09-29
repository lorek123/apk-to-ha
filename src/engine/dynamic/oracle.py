# SPDX-License-Identifier: MIT
"""P2-7 public entry point — dynamic protocol oracle.

Runs the APK in a redroid container, injects the Frida agent, collects
live traffic, and reconciles it against the static IR.

Skipped gracefully when:
  - Docker is unavailable
  - binder_linux module cannot be loaded
  - All signing traces have confidence ≥ 0.9 and zero unresolved fields
  - The caller passes skip=True
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from ..ir.models import DiscoveryType, ProtocolIR
from .adb_client import connect, ensure_frida_server, install_apk, launch_app, start_frida_server
from .frida_runner import FridaUnavailableError, capture
from .ir_reconciler import ReconciliationReport, reconcile
from .mock_device_server import mock_device
from .redroid_runner import RedroidUnavailableError, redroid

_LOGGER = logging.getLogger(__name__)

# Confidence threshold below which we always run the oracle
_ORACLE_CONFIDENCE_THRESHOLD = 0.9
_CAPTURE_SECONDS = 30


def unresolved_ir_fields(ir: ProtocolIR) -> list[str]:
    """What the oracle could resolve (SPEC P2-7), as human-readable reasons.

    Limited to gaps a live capture actually fills: unverified signing, low-confidence
    commands/events, response schemas of commands that await a reply, and
    discovery details.
    """
    gaps: list[str] = []
    for t in ir.signing_traces:
        if t.confidence < _ORACLE_CONFIDENCE_THRESHOLD or t.unresolved:
            gaps.append(f"signing trace {t.source_method} (confidence {t.confidence:.2f})")
    for ep in ir.commands + ir.events:
        if ep.confidence < _ORACLE_CONFIDENCE_THRESHOLD:
            gaps.append(f"{ep.cmd}: confidence {ep.confidence:.2f}")
    for ep in ir.commands:
        if ep.awaits_response and not ep.response_fields:
            gaps.append(f"{ep.cmd}: response schema unknown")
    if ir.discovery.type != DiscoveryType.NONE and ir.discovery.port is None:
        gaps.append(f"discovery ({ir.discovery.type.value}): port unknown")
    return gaps


def _should_skip(ir: ProtocolIR) -> bool:
    """SPEC P2-7: skip when static confidence >= 0.9 on all traces AND zero unresolved IR fields."""
    return not unresolved_ir_fields(ir)


async def run(
    apk_path: Path,
    ir: ProtocolIR,
    package_name: str | None = None,
    capture_seconds: int = _CAPTURE_SECONDS,
    force: bool = False,
) -> ReconciliationReport:
    """Run the oracle against *apk_path* and return a ReconciliationReport.

    If *force* is False and static confidence is already ≥ 0.9, returns an
    empty report (confidence_boost=0) without launching the container.
    """
    gaps = unresolved_ir_fields(ir)
    if not force and not gaps:
        _LOGGER.info("oracle: skipped — static IR has nothing left for a live capture to resolve")
        return ReconciliationReport()
    _LOGGER.info("oracle: running to resolve %d gap(s): %s", len(gaps), "; ".join(gaps[:5]))

    pkg = package_name or ir.package_name
    t0 = time.time()

    try:
        async with redroid():
            await connect()
            await install_apk(apk_path)
            await ensure_frida_server()
            await start_frida_server()

            async with mock_device(
                ws_port=ir.transport.port or 8887,
                udp_port=ir.discovery.port,
                auth_cmd=ir.auth.handshake_cmd or "grantAccess",
                state_cmd=ir.state.push_cmd or "gin",
            ):
                await launch_app(pkg)
                session = await capture(pkg, capture_seconds=capture_seconds)

    except RedroidUnavailableError as exc:
        _LOGGER.warning("oracle: redroid unavailable — skipping P2-7 (%s)", exc)
        return ReconciliationReport()
    except FridaUnavailableError as exc:
        _LOGGER.warning("oracle: frida unavailable — skipping P2-7 (%s)", exc)
        return ReconciliationReport()
    except Exception as exc:
        _LOGGER.error("oracle: unexpected error — skipping P2-7 (%s)", exc)
        return ReconciliationReport()

    elapsed = int((time.time() - t0) * 1000)
    _LOGGER.info(
        "oracle: capture complete in %dms — hmac=%d http=%d ws=%d",
        elapsed,
        len(session.hmac_calls),
        len(session.http_calls),
        len(session.ws_frames),
    )

    report = reconcile(session, ir)
    return report
