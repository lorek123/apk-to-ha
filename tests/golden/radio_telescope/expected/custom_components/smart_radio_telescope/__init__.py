# SPDX-License-Identifier: MIT
"""Smart Radio Telescope Home Assistant integration."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from smart_radio_telescope_sdk import SmartRadioTelescopeClient

from .const import DEFAULT_PORT
from .coordinator import SmartRadioTelescopeCoordinator

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.NUMBER,
]


@dataclass
class SmartRadioTelescopeRuntimeData:
    coordinator: SmartRadioTelescopeCoordinator
    client: SmartRadioTelescopeClient


type SmartRadioTelescopeConfigEntry = ConfigEntry[SmartRadioTelescopeRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: SmartRadioTelescopeConfigEntry) -> bool:
    session = aiohttp_client.async_get_clientsession(hass)
    client = SmartRadioTelescopeClient(
        host=entry.data[CONF_HOST],
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        session=session,
    )
    coordinator = SmartRadioTelescopeCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = SmartRadioTelescopeRuntimeData(coordinator=coordinator, client=client)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SmartRadioTelescopeConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await entry.runtime_data.client.disconnect()
    return unload_ok
