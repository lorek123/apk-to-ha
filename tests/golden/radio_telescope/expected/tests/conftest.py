# SPDX-License-Identifier: MIT
"""Fixtures for Smart Radio Telescope runtime tests: a mock device serving its local HTTP API."""
from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import pytest
from aiohttp import web

POLL_METHOD = "GET"
POLL_PATH = "/status"
INITIAL_STATE: dict[str, Any] = json.loads("{\"az\": 1}")


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Make custom_components/ loadable in every test."""


@pytest.fixture(autouse=True)
def auto_enable_sockets(socket_enabled: None) -> None:
    """The mock device is a real server on 127.0.0.1 (the sandbox runs with no network)."""


class MockDevice:
    """HTTP server on 127.0.0.1: serves state at POLL_PATH, records every other request."""

    def __init__(self) -> None:
        self.state: dict[str, Any] = dict(INITIAL_STATE)
        self.requests: list[tuple[str, str, Any]] = []
        self.queries: list[dict[str, str]] = []
        self.port = 0
        self._runner: web.AppRunner | None = None

    async def start(self, port: int = 0) -> None:
        app = web.Application()
        app.router.add_route(POLL_METHOD, POLL_PATH, self._handle_state)
        app.router.add_route("*", "/{tail:.*}", self._handle_command)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", port, reuse_address=True)
        await site.start()
        self.port = self._runner.addresses[0][1]

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None

    def set_state(self, **changes: Any) -> None:
        self.state.update(changes)

    async def _handle_state(self, request: web.Request) -> web.Response:
        return web.json_response(self.state)

    async def _handle_command(self, request: web.Request) -> web.Response:
        body: Any = None
        if request.content_type == "application/x-www-form-urlencoded":
            body = {k: str(v) for k, v in (await request.post()).items()}
        elif request.can_read_body:
            body = await request.json()
        self.requests.append((request.method, request.path, body))
        self.queries.append(dict(request.query))
        return web.json_response({"ok": True})


@pytest.fixture
async def mock_device() -> AsyncIterator[MockDevice]:
    device = MockDevice()
    await device.start()
    yield device
    await device.stop()
