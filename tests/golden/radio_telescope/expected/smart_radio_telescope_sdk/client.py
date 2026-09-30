# SPDX-License-Identifier: MIT
"""HTTP client for Smart Radio Telescope (local JSON API, polled)."""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

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

    async def system(self) -> dict[str, Any]:
        """GET /system."""
        result = await self._request(
            "GET",
            "/system",
        )
        return result if isinstance(result, dict) else {"result": result}

    async def goto(
        self,
        *,
        az: float,
        el: float,
        pol: float,
    ) -> None:
        """POST /goto."""
        body: dict[str, Any] = {
            "az": az,
            "el": el,
            "pol": pol,
        }
        await self._request(
            "POST",
            "/goto",
            body=body,
        )

    async def goto_radec(
        self,
        *,
        ra_deg: float,
        dec_deg: float,
        lat: float,
        lon: float,
    ) -> None:
        """POST /goto/radec."""
        body: dict[str, Any] = {
            "ra_deg": ra_deg,
            "dec_deg": dec_deg,
            "lat": lat,
            "lon": lon,
        }
        await self._request(
            "POST",
            "/goto/radec",
            body=body,
        )

    async def home(
        self,
        *,
        axis: str,
    ) -> None:
        """POST /home/{axis}."""
        await self._request(
            "POST",
            f"/home/{quote(str(axis), safe="")}",
        )

    async def move(
        self,
        *,
        axis: str,
        degrees: float,
    ) -> None:
        """POST /move."""
        body: dict[str, Any] = {
            "axis": axis,
            "degrees": degrees,
        }
        await self._request(
            "POST",
            "/move",
            body=body,
        )

    async def jog(
        self,
        *,
        az_dps: float,
        el_dps: float,
    ) -> None:
        """POST /jog."""
        body: dict[str, Any] = {
            "az_dps": az_dps,
            "el_dps": el_dps,
        }
        await self._request(
            "POST",
            "/jog",
            body=body,
        )

    async def scan(
        self,
        *,
        sweep: str,
        pattern: str,
        s0: float,
        s1: float,
        t0: float,
        t1: float,
        speed: float,
        rows: int,
    ) -> None:
        """POST /scan."""
        body: dict[str, Any] = {
            "sweep": sweep,
            "pattern": pattern,
            "s0": s0,
            "s1": s1,
            "t0": t0,
            "t1": t1,
            "speed": speed,
            "rows": rows,
        }
        await self._request(
            "POST",
            "/scan",
            body=body,
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
                    raise SmartRadioTelescopeAuthError(f"{method} {path}: HTTP {resp.status}")
                resp.raise_for_status()
                if resp.content_type == "application/json":
                    return await resp.json()
                return await resp.text()
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise SmartRadioTelescopeConnectionError(f"{method} {path} failed: {exc!r}") from exc
