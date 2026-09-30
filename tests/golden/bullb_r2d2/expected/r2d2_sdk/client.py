# SPDX-License-Identifier: MIT
"""WebSocket client for Build Your Own R2-D2."""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

import aiohttp

from .const import ACTION_TO_MODE, CMD_AUTH, CMD_STATE_PUSH, DEFAULT_PORT
from .models import RobotState

_LOGGER = logging.getLogger(__name__)

# How long connect() waits for the first gin push after grantAccess.
FIRST_STATE_TIMEOUT = 10.0


class R2D2ConnectionError(Exception):
    """Raised when the device cannot be reached or never sends its state."""


class R2D2AuthError(R2D2ConnectionError):
    """Raised when the device answers grantAccess but rejects the pairing."""


class R2D2Client:
    """Manages the WebSocket connection to a Build Your Own R2-D2 robot."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._session = session
        self._own_session = session is None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._state: RobotState = RobotState()
        self._state_callbacks: list[Callable[[RobotState], None]] = []
        self._disconnect_callbacks: list[Callable[[], None]] = []
        self._listen_task: asyncio.Task[None] | None = None
        self._first_state = asyncio.Event()
        self._auth_rejected: object = None
        self._closing = False

    @property
    def state(self) -> RobotState:
        return self._state

    @property
    def host(self) -> str:
        return self._host

    @property
    def connected(self) -> bool:
        return self._ws is not None and not self._ws.closed

    def on_state_update(self, callback: Callable[[RobotState], None]) -> None:
        self._state_callbacks.append(callback)

    def on_disconnect(self, callback: Callable[[], None]) -> None:
        """Called when the connection drops without disconnect() being called."""
        self._disconnect_callbacks.append(callback)

    async def connect(
        self,
        device_uuid: str,
        device_name: str = "Home Assistant",
        first_state_timeout: float = FIRST_STATE_TIMEOUT,
    ) -> RobotState:
        """Connect, pair with a stable *device_uuid*, and wait for the first state push.

        Raises R2D2ConnectionError (and leaves nothing open) on failure.
        """
        if self.connected:
            return self._state
        self._closing = False
        self._first_state.clear()
        self._auth_rejected = None
        if self._own_session and self._session is None:
            self._session = aiohttp.ClientSession()
        assert self._session is not None

        url = f"ws://{self._host}:{self._port}"
        _LOGGER.debug("Connecting to %s", url)
        try:
            self._ws = await self._session.ws_connect(url, heartbeat=30)
            self._listen_task = asyncio.create_task(self._listen())
            grant = {"cmd": CMD_AUTH, "uuid": device_uuid, "device_name": device_name}
            await self._ws.send_str(json.dumps(grant))
            async with asyncio.timeout(first_state_timeout):
                await self._first_state.wait()
        except (aiohttp.ClientError, OSError, TimeoutError) as exc:
            await self.disconnect()
            raise R2D2ConnectionError(
                f"Cannot connect to {self._host}:{self._port}: {exc!r}"
            ) from exc
        if self._auth_rejected is not None:
            await self.disconnect()
            raise R2D2AuthError(
                f"{self._host} rejected {CMD_AUTH} (result={self._auth_rejected!r})"
            )
        return self._state

    async def disconnect(self) -> None:
        self._closing = True
        if self._listen_task:
            self._listen_task.cancel()
            self._listen_task = None
        if self._ws and not self._ws.closed:
            await self._ws.close()
        self._ws = None
        if self._own_session and self._session:
            await self._session.close()
            self._session = None

    async def send_command(self, cmd: str, **params: Any) -> None:
        if self._ws is None or self._ws.closed:
            raise R2D2ConnectionError(f"{cmd}: not connected")
        payload: dict[str, Any] = {"cmd": cmd, **params}
        try:
            await self._ws.send_str(json.dumps(payload))
        except (aiohttp.ClientError, ConnectionResetError) as exc:
            raise R2D2ConnectionError(f"{cmd} failed: {exc!r}") from exc

    async def set_power(self, enable: bool) -> None:
        await self.send_command("power", enable=enable)

    async def set_mute(self, enable: bool) -> None:
        await self.send_command("mute", enable=enable)

    async def set_face_detection(self, enable: bool) -> None:
        await self.send_command("face_detection", enable=enable)

    async def set_voice_recognition(self, enable: bool) -> None:
        await self.send_command("voice_recognition", enable=enable)

    async def set_mode(self, action_name: str) -> None:
        mode = ACTION_TO_MODE.get(action_name)
        if mode is None:
            raise ValueError(f"Unknown mode: {action_name!r}")
        await self.send_command("mode", mode=mode)

    async def press_reset_mcu(self) -> None:
        await self.send_command("reset_mcu")

    async def press_d_head_power(self) -> None:
        await self.send_command("d-head-power")

    async def press_d_leg_power(self) -> None:
        await self.send_command("d-leg-power")

    async def play_sound(
        self,
        *,
        interrupt: int,
        sound_id: str,
    ) -> None:
        """play_sound."""
        params: dict[str, Any] = {
            "interrupt": interrupt,
            "sound_id": sound_id,
        }
        await self.send_command("play_sound", **params)

    async def move_head(
        self,
        *,
        angle: str,
    ) -> None:
        """move-head."""
        params: dict[str, Any] = {
            "angle": angle,
        }
        await self.send_command("move-head", **params)

    async def self_update(
        self,
        *,
        url: str,
    ) -> None:
        """self_update."""
        params: dict[str, Any] = {
            "url": url,
        }
        await self.send_command("self_update", **params)

    async def change_name(
        self,
        *,
        new_name: str,
    ) -> None:
        """change_name."""
        params: dict[str, Any] = {
            "new_name": new_name,
        }
        await self.send_command("change_name", **params)

    async def unpair(
        self,
        *,
        uuid: str,
    ) -> None:
        """unpair."""
        params: dict[str, Any] = {
            "uuid": uuid,
        }
        await self.send_command("unpair", **params)

    async def connect_wifi(
        self,
        *,
        ssid: str,
        wifi_pw: str,
        enable: bool,
    ) -> None:
        """connectWifi."""
        params: dict[str, Any] = {
            "ssid": ssid,
            "wifi_pw": wifi_pw,
            "enable": enable,
        }
        await self.send_command("connectWifi", **params)

    async def head_shift(
        self,
        *,
        angle: int,
        interrupt: int,
    ) -> None:
        """head-shift."""
        params: dict[str, Any] = {
            "angle": angle,
            "interrupt": interrupt,
        }
        await self.send_command("head-shift", **params)

    async def move(
        self,
        *,
        angle: str,
        enable: bool,
    ) -> None:
        """move."""
        params: dict[str, Any] = {
            "angle": angle,
            "enable": enable,
        }
        await self.send_command("move", **params)

    async def head_dir(
        self,
        *,
        dir: str,
    ) -> None:
        """head-dir."""
        params: dict[str, Any] = {
            "dir": dir,
        }
        await self.send_command("head-dir", **params)

    async def _listen(self) -> None:
        ws = self._ws
        assert ws is not None
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    self._dispatch(msg.data)
                elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            return
        except Exception:
            _LOGGER.exception("WebSocket listener error")
        if self._closing:
            return
        _LOGGER.debug("Connection to %s lost", self._host)
        self._ws = None
        for cb in self._disconnect_callbacks:
            cb()

    def _dispatch(self, raw: str) -> None:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return
        cmd = data.get("cmd")
        if cmd == CMD_STATE_PUSH:
            self._state = RobotState.from_dict(data)
            self._first_state.set()
            for cb in self._state_callbacks:
                cb(self._state)
