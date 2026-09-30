# SPDX-License-Identifier: MIT
"""DataUpdateCoordinator for Smart Radio Telescope (polls the device's local HTTP API)."""
from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from smart_radio_telescope_sdk import (
    RobotState,
    SmartRadioTelescopeAuthError,
    SmartRadioTelescopeClient,
    SmartRadioTelescopeConnectionError,
)

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# How often GET /status is fetched.
POLL_INTERVAL = timedelta(seconds=30)


class SmartRadioTelescopeCoordinator(DataUpdateCoordinator[RobotState]):
    """Polls Smart Radio Telescope; a failed poll marks entities unavailable until the next success."""

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: SmartRadioTelescopeClient,
    ) -> None:
        super().__init__(
            hass, _LOGGER, config_entry=entry, name=DOMAIN, update_interval=POLL_INTERVAL
        )
        self.client = client

    async def _async_update_data(self) -> RobotState:
        try:
            return await self.client.get_state()
        except SmartRadioTelescopeAuthError as exc:
            # Credentials rejected: HA starts the reauth flow.
            raise ConfigEntryAuthFailed(str(exc)) from exc
        except SmartRadioTelescopeConnectionError as exc:
            raise UpdateFailed(str(exc)) from exc
