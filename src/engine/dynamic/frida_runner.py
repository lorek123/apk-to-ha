# SPDX-License-Identifier: MIT
"""Python Frida orchestration: spawn app, inject agent, collect events."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

try:
    import frida

    _FRIDA_AVAILABLE = True
except ImportError:  # pragma: no cover
    _FRIDA_AVAILABLE = False

from .capture_model import (
    CaptureSession,
    HmacCapture,
    HttpCapture,
    WsCapture,
)

_LOGGER = logging.getLogger(__name__)
_AGENT_JS = Path(__file__).parent / "frida_agent.js"

# Default capture window: 30 seconds after the app launches
DEFAULT_CAPTURE_SECONDS = 30


class FridaUnavailableError(Exception):
    """Raised when frida is not installed or frida-server is unreachable."""


async def capture(
    package_name: str,
    capture_seconds: int = DEFAULT_CAPTURE_SECONDS,
) -> CaptureSession:
    """Spawn *package_name* on the connected device, inject the agent, collect events.

    The caller must have already connected ADB and started frida-server on the device.
    """
    if not _FRIDA_AVAILABLE:
        raise FridaUnavailableError("frida Python package not installed")

    session_obj = CaptureSession()
    events: list[dict[str, Any]] = []
    ready_event = asyncio.Event()
    loop = asyncio.get_event_loop()

    def _on_message(message: dict[str, Any], _data: bytes | None) -> None:
        if message.get("type") == "send":
            payload = message.get("payload", {})
            events.append(payload)
            if payload.get("type") == "agent_ready":
                loop.call_soon_threadsafe(ready_event.set)
        elif message.get("type") == "error":
            _LOGGER.warning("frida_agent error: %s", message.get("description", ""))

    agent_code = _AGENT_JS.read_text()

    # Run blocking Frida calls in a thread executor
    def _inject() -> tuple[Any, Any]:
        device = frida.get_device("localhost:5555", timeout=10)
        pid = device.spawn([package_name])
        proc = device.attach(pid)
        script = proc.create_script(agent_code)
        script.on("message", _on_message)
        script.load()
        device.resume(pid)
        return proc, script

    try:
        proc, script = await loop.run_in_executor(None, _inject)
    except Exception as exc:
        raise FridaUnavailableError(f"Frida injection failed: {exc}") from exc

    _LOGGER.info("frida: agent injected into %s, capturing for %ds", package_name, capture_seconds)

    # Wait for agent_ready signal then run the capture window
    try:
        await asyncio.wait_for(ready_event.wait(), timeout=15)
    except TimeoutError:
        _LOGGER.warning("frida: agent_ready not received within 15s — continuing anyway")

    await asyncio.sleep(capture_seconds)

    # Teardown
    def _cleanup() -> None:
        try:
            script.unload()
        except Exception:
            pass
        try:
            proc.detach()
        except Exception:
            pass

    await loop.run_in_executor(None, _cleanup)

    # Parse collected events into typed models
    for ev in events:
        t = ev.get("type")
        if t == "hmac_call":
            session_obj.hmac_calls.append(
                HmacCapture(
                    algorithm=ev.get("algorithm", "unknown"),
                    key_hex=ev.get("key_hex", ""),
                    input_hex=ev.get("input_hex", ""),
                    output_hex=ev.get("output_hex", ""),
                    timestamp_ms=ev.get("ts", 0),
                )
            )
        elif t == "http_call":
            session_obj.http_calls.append(
                HttpCapture(
                    method=ev.get("method", ""),
                    url=ev.get("url", ""),
                    request_headers=ev.get("request_headers") or {},
                    request_body=ev.get("request_body"),
                    response_code=ev.get("response_code", 0),
                    response_body=ev.get("response_body"),
                    timestamp_ms=ev.get("ts", 0),
                )
            )
        elif t == "ws_send":
            session_obj.ws_frames.append(
                WsCapture(
                    direction="send",
                    frame=ev.get("frame", ""),
                    timestamp_ms=ev.get("ts", 0),
                )
            )
        elif t == "ws_recv":
            session_obj.ws_frames.append(
                WsCapture(
                    direction="recv",
                    frame=ev.get("frame", ""),
                    timestamp_ms=ev.get("ts", 0),
                )
            )

    _LOGGER.info(
        "frida: captured hmac=%d http=%d ws=%d",
        len(session_obj.hmac_calls),
        len(session_obj.http_calls),
        len(session_obj.ws_frames),
    )
    return session_obj
