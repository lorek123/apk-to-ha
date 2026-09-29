# SPDX-License-Identifier: MIT
"""Typed models for events captured by the Frida agent."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HmacCapture:
    """One Mac.doFinal() call intercepted by the Frida agent."""

    algorithm: str  # e.g. "HmacSHA256"
    key_hex: str  # raw key bytes as hex
    input_hex: str  # raw input bytes as hex
    output_hex: str  # raw HMAC output bytes as hex
    timestamp_ms: int = 0


@dataclass
class HttpCapture:
    """One HTTP request/response pair captured from OkHttp3 or HttpURLConnection."""

    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_code: int = 0
    response_body: str | None = None
    timestamp_ms: int = 0


@dataclass
class WsCapture:
    """One WebSocket frame (text only) captured from OkHttp WS."""

    direction: str  # "send" | "recv"
    frame: str  # raw text content
    timestamp_ms: int = 0


@dataclass
class UdpCapture:
    """UDP datagram sent by the app (discovery broadcasts)."""

    dst_host: str
    dst_port: int
    payload_hex: str
    timestamp_ms: int = 0


@dataclass
class CaptureSession:
    """Aggregated captures from one oracle run."""

    hmac_calls: list[HmacCapture] = field(default_factory=list)
    http_calls: list[HttpCapture] = field(default_factory=list)
    ws_frames: list[WsCapture] = field(default_factory=list)
    udp_sends: list[UdpCapture] = field(default_factory=list)
    duration_ms: int = 0
    error: str | None = None

    @property
    def is_empty(self) -> bool:
        return not (self.hmac_calls or self.http_calls or self.ws_frames or self.udp_sends)

    def ws_sends(self) -> list[WsCapture]:
        return [f for f in self.ws_frames if f.direction == "send"]

    def ws_recvs(self) -> list[WsCapture]:
        return [f for f in self.ws_frames if f.direction == "recv"]
