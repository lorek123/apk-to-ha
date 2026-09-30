# SPDX-License-Identifier: MIT
"""Polls Firepit over Bluetooth."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from firepit_sdk import FirepitClient, FirepitConnectionError
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, POLL_INTERVAL

if TYPE_CHECKING:
    from . import FirepitConfigEntry

_LOGGER = logging.getLogger(__name__)


class FirepitCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """State of one device: {key: value}; None for a value the device didn't give."""

    config_entry: FirepitConfigEntry

    def __init__(
        self, hass: HomeAssistant, entry: FirepitConfigEntry, client: FirepitClient
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=POLL_INTERVAL,
        )
        self.client = client
        self.device_info: dict[str, str] = {}

    async def _async_setup(self) -> None:
        try:
            self.device_info = await self.client.read_device_info()
        except FirepitConnectionError as err:
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="cannot_connect",
                translation_placeholders={"error": str(err)},
            ) from err

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            return await self.client.read_state()
        except FirepitConnectionError as err:
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="cannot_connect",
                translation_placeholders={"error": str(err)},
            ) from err

    def set_value(self, key: str, value: Any) -> None:
        """The device accepted a write: show it now instead of reconnecting to re-read."""
        self.async_set_updated_data({**(self.data or {}), key: value})
