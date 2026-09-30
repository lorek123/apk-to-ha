# SPDX-License-Identifier: MIT
"""HTTP client for Smart Radio Telescope (local JSON API, polled)."""
from __future__ import annotations

import logging
from typing import Any

import aiohttp

from .const import DEFAULT_PORT
from .models import RobotState

_LOGGER = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10.0


class SmartRadioTelescopeConnectionError(Exception):
    """Raised when the device can't be reached or answers with an error."""


class SmartRadioTelescopeAuthError(SmartRadioTelescopeConnectionError):
    """Raised when the device refuses the request (HTTP 401/403)."""


class SmartRadioTelescopeClient:
    """Talks to Smart Radio Telescope at http://host:port."""

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
        """Fetch current state (GET /status)."""
        data = await self._request("GET", "/status")
        if not isinstance(data, dict):
            raise SmartRadioTelescopeConnectionError(f"Unexpected state payload: {data!r:.100}")
        return RobotState.from_dict(data)

    async def disconnect(self) -> None:
        """Close the session if this client created it."""
        if self._own_session and self._session is not None:
            await self._session.close()
            self._session = None

    async def press_shutdown(self) -> None:
        await self._request("POST", "/shutdown", {})

    async def press_home(self) -> None:
        await self._request("POST", "/home", {})

    async def press_stop(self) -> None:
        await self._request("POST", "/stop", {})

    async def press_sleep(self) -> None:
        await self._request("POST", "/sleep", {})

    async def press_wake(self) -> None:
        await self._request("POST", "/wake", {})

    async def set_adc_rate(self, value: float) -> None:
        await self._request(
            "POST",
            "/adc_rate",
            {"hz": int(value)},
        )

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
                    raise SmartRadioTelescopeAuthError(f"{method} {path}: HTTP {resp.status}")
                resp.raise_for_status()
                if resp.content_type == "application/json":
                    return await resp.json()
                return await resp.text()
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise SmartRadioTelescopeConnectionError(f"{method} {path} failed: {exc!r}") from exc
