# SPDX-License-Identifier: MIT
"""NOVA Home Assistant integration."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_API_KEY, CONF_URL, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType
from nova_sdk import NovaClient

from .const import DOMAIN
from .coordinator import NovaCoordinator
from .services import async_setup_services

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
]


@dataclass
class NovaRuntimeData:
    coordinator: NovaCoordinator
    client: NovaClient


type NovaConfigEntry = ConfigEntry[NovaRuntimeData]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the integration's actions (they target a config entry by ID)."""
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: NovaConfigEntry) -> bool:
    client = NovaClient(
        url=entry.data[CONF_URL],
        session=aiohttp_client.async_get_clientsession(hass, verify_ssl=entry.data[CONF_VERIFY_SSL]),
        api_key=entry.data[CONF_API_KEY],
    )
    coordinator = NovaCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = NovaRuntimeData(coordinator=coordinator, client=client)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: NovaConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await entry.runtime_data.client.disconnect()
    return unload_ok
