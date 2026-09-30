# SPDX-License-Identifier: MIT
"""DataUpdateCoordinator for Inkcast (polls the device's local HTTP API)."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from inkcast_sdk import (
    InkcastAuthError,
    InkcastClient,
    InkcastConnectionError,
    RobotState,
)

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# How often GET /api/status is fetched.
POLL_INTERVAL = timedelta(seconds=30)


class InkcastCoordinator(DataUpdateCoordinator[RobotState]):
    """Polls Inkcast; a failed poll marks entities unavailable until the next success."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: InkcastClient,
    ) -> None:
        super().__init__(
            hass, _LOGGER, config_entry=entry, name=DOMAIN, update_interval=POLL_INTERVAL
        )
        self.client = client

    async def _async_update_data(self) -> RobotState:
        try:
            return await self.client.get_state()
        except InkcastAuthError as exc:
            # Credentials rejected: HA starts the reauth flow.
            raise ConfigEntryAuthFailed(str(exc)) from exc
        except InkcastConnectionError as exc:
            raise UpdateFailed(str(exc)) from exc
