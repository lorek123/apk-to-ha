# SPDX-License-Identifier: MIT
"""HTTP client for Inkcast (local JSON API, polled)."""
from __future__ import annotations

import logging
from typing import Any

import aiohttp

from .const import DEFAULT_PORT
from .models import RobotState

_LOGGER = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10.0


class InkcastConnectionError(Exception):
    """Raised when the device can't be reached or answers with an error."""


class InkcastAuthError(InkcastConnectionError):
    """Raised when the device refuses the request (HTTP 401/403)."""


class InkcastClient:
    """Talks to Inkcast at http://host:port."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self._host = host
        self._base = f"http://{host}:{port}"
        self._session = session
        self._own_session = session is None

    @property
    def host(self) -> str:
        return self._host

    async def get_state(self) -> RobotState:
        """Fetch current state (GET /api/status)."""
        data = await self._request("GET", "/api/status")
        if not isinstance(data, dict):
            raise InkcastConnectionError(f"Unexpected state payload: {data!r:.100}")
        return RobotState.from_dict(data)

    async def disconnect(self) -> None:
        """Close the session if this client created it."""
        if self._own_session and self._session is not None:
            await self._session.close()
            self._session = None

    async def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        if self._session is None:
            self._session = aiohttp.ClientSession()
        try:
            async with self._session.request(
                method,
                self._base + path,
                json=body,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ) as resp:
                if resp.status in (401, 403):
                    raise InkcastAuthError(f"{method} {path}: HTTP {resp.status}")
                resp.raise_for_status()
                if resp.content_type == "application/json":
                    return await resp.json()
                return await resp.text()
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise InkcastConnectionError(f"{method} {path} failed: {exc!r}") from exc
