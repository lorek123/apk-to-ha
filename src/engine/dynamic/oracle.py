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

from ..ir.models import ProtocolIR
from .adb_client import connect, ensure_frida_server, install_apk, launch_app, start_frida_server
from .frida_runner import FridaUnavailableError, capture
from .ir_reconciler import ReconciliationReport, reconcile
from .mock_device_server import mock_device
from .redroid_runner import RedroidUnavailableError, redroid

_LOGGER = logging.getLogger(__name__)

# Confidence threshold below which we always run the oracle
_ORACLE_CONFIDENCE_THRESHOLD = 0.9
_CAPTURE_SECONDS = 30


def _should_skip(ir: ProtocolIR) -> bool:
    """Return True if the static analysis is already high-confidence enough."""
    if not ir.signing_traces:
        return False
    all_high = all(t.confidence >= _ORACLE_CONFIDENCE_THRESHOLD for t in ir.signing_traces)
    no_unresolved = all(not t.unresolved for t in ir.signing_traces)
    return all_high and no_unresolved


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
    if not force and _should_skip(ir):
        _LOGGER.info(
            "oracle: skipped — static confidence already ≥ %.1f", _ORACLE_CONFIDENCE_THRESHOLD
        )
        return ReconciliationReport()

    pkg = package_name or ir.package_name
    t0 = time.time()

    try:
        async with redroid() as container_id:
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
