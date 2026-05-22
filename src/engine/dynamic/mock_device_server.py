# SPDX-License-Identifier: MIT
"""Minimal mock device server that makes the app generate real network traffic.

Listens on the device's expected ports (WebSocket + UDP) and returns canned
responses so the app proceeds past discovery → auth → state, generating the
signing calls and API requests the Frida agent needs to capture.
"""
from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator

from aiohttp import web

_LOGGER = logging.getLogger(__name__)


def _ws_handler_factory(auth_cmd: str, state_cmd: str) -> web.WebSocketResponse:
    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        _LOGGER.debug("mock: WebSocket client connected from %s", request.remote)

        async for msg in ws:
            if msg.type != web.WSMsgType.TEXT:
                continue
            try:
                data = json.loads(msg.data)
            except json.JSONDecodeError:
                continue

            cmd = data.get("cmd", "")
            _LOGGER.debug("mock: WS recv cmd=%r", cmd)

            if cmd == auth_cmd:
                await ws.send_str(json.dumps({"cmd": auth_cmd, "result": "ok", "token": "mock_token_123"}))
                # After auth, push a fake state so the app thinks everything is normal
                await asyncio.sleep(0.2)
                await ws.send_str(json.dumps({"cmd": state_cmd, "state": "mock", "status": 1}))
            else:
                # Echo back a generic ack
                await ws.send_str(json.dumps({"cmd": cmd, "result": "ok"}))

        return ws

    return ws_handler


class MockDeviceServer:
    """Async context manager that runs WS + UDP mock server."""

    def __init__(self, ws_port: int, udp_port: int | None, auth_cmd: str, state_cmd: str) -> None:
        self.ws_port = ws_port
        self.udp_port = udp_port
        self.auth_cmd = auth_cmd
        self.state_cmd = state_cmd
        self._runner: web.AppRunner | None = None
        self._udp_transport: asyncio.BaseTransport | None = None

    async def start(self) -> None:
        app = web.Application()
        app.router.add_get("/", _ws_handler_factory(self.auth_cmd, self.state_cmd))
        app.router.add_get("/ws", _ws_handler_factory(self.auth_cmd, self.state_cmd))

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", self.ws_port)
        await site.start()
        _LOGGER.info("mock: WebSocket server listening on :%d", self.ws_port)

        if self.udp_port:
            await self._start_udp()

    async def _start_udp(self) -> None:
        loop = asyncio.get_event_loop()

        class _UdpProtocol(asyncio.DatagramProtocol):
            def __init__(inner_self) -> None:
                inner_self.transport: asyncio.DatagramTransport | None = None

            def connection_made(inner_self, transport: asyncio.BaseTransport) -> None:
                inner_self.transport = transport  # type: ignore[assignment]

            def datagram_received(inner_self, data: bytes, addr: tuple) -> None:
                _LOGGER.debug("mock: UDP recv %d bytes from %s", len(data), addr)
                # Respond with a fake device discovery packet
                reply = json.dumps({
                    "cmd": "devInfo",
                    "ip": "127.0.0.1",
                    "port": self.ws_port,
                    "model": "MockDevice",
                }).encode()
                if inner_self.transport:
                    inner_self.transport.sendto(reply, addr)  # type: ignore[union-attr]

        transport, _ = await loop.create_datagram_endpoint(
            _UdpProtocol,
            local_addr=("0.0.0.0", self.udp_port),
        )
        self._udp_transport = transport
        _LOGGER.info("mock: UDP server listening on :%d", self.udp_port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
        if self._udp_transport:
            self._udp_transport.close()


@asynccontextmanager
async def mock_device(
    ws_port: int,
    udp_port: int | None,
    auth_cmd: str = "grantAccess",
    state_cmd: str = "gin",
) -> AsyncIterator[MockDeviceServer]:
    server = MockDeviceServer(ws_port, udp_port, auth_cmd, state_cmd)
    await server.start()
    try:
        yield server
    finally:
        await server.stop()
