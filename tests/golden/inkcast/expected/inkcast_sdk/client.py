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


def _scalars(values: dict[str, Any] | None) -> dict[str, str] | None:
    """Query/form values as strings (aiohttp rejects bools): True → "true"."""
    if not values:
        return None
    return {k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in values.items()}


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

    async def download(
        self,
        *,
        path: str,
    ) -> dict[str, Any]:
        """GET /download."""
        query: dict[str, Any] = {
            "path": path,
        }
        result = await self._request(
            "GET",
            "/download",
            params=query,
        )
        return result if isinstance(result, dict) else {"result": result}

    async def files(
        self,
        *,
        path: str,
    ) -> dict[str, Any]:
        """GET /api/files."""
        query: dict[str, Any] = {
            "path": path,
        }
        result = await self._request(
            "GET",
            "/api/files",
            params=query,
        )
        return result if isinstance(result, dict) else {"result": result}

    async def get_settings(self) -> dict[str, Any]:
        """GET /api/settings."""
        result = await self._request(
            "GET",
            "/api/settings",
        )
        return result if isinstance(result, dict) else {"result": result}

    async def post_settings(
        self,
        *,
        body: dict[str, Any],
    ) -> None:
        """POST /api/settings."""
        await self._request(
            "POST",
            "/api/settings",
            body,
        )

    async def delete(
        self,
        *,
        path: str,
        type: str,
    ) -> None:
        """POST /delete."""
        form: dict[str, Any] = {
            "path": path,
            "type": type,
        }
        await self._request(
            "POST",
            "/delete",
            data=form,
        )

    async def rename(
        self,
        *,
        path: str,
        name: str,
    ) -> None:
        """POST /rename."""
        form: dict[str, Any] = {
            "path": path,
            "name": name,
        }
        await self._request(
            "POST",
            "/rename",
            data=form,
        )

    async def move(
        self,
        *,
        path: str,
        dest: str,
    ) -> None:
        """POST /move."""
        form: dict[str, Any] = {
            "path": path,
            "dest": dest,
        }
        await self._request(
            "POST",
            "/move",
            data=form,
        )

    async def mkdir(
        self,
        *,
        name: str,
        path: str,
    ) -> None:
        """POST /mkdir."""
        form: dict[str, Any] = {
            "name": name,
            "path": path,
        }
        await self._request(
            "POST",
            "/mkdir",
            data=form,
        )

    async def _request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        if self._session is None:
            self._session = aiohttp.ClientSession()
        try:
            async with self._session.request(
                method,
                self._base + path,
                json=body,
                params=_scalars(params),
                data=_scalars(data),
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
