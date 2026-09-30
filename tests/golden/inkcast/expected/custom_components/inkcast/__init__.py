# SPDX-License-Identifier: MIT
"""Inkcast Home Assistant integration."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType
from inkcast_sdk import InkcastClient

from .const import DEFAULT_PORT, DOMAIN
from .coordinator import InkcastCoordinator
from .services import async_setup_services

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
]


@dataclass
class InkcastRuntimeData:
    coordinator: InkcastCoordinator
    client: InkcastClient


type InkcastConfigEntry = ConfigEntry[InkcastRuntimeData]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the integration's actions (they target a config entry by ID)."""
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: InkcastConfigEntry) -> bool:
    session = aiohttp_client.async_get_clientsession(hass)
    client = InkcastClient(
        host=entry.data[CONF_HOST],
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        session=session,
    )
    coordinator = InkcastCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = InkcastRuntimeData(coordinator=coordinator, client=client)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: InkcastConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await entry.runtime_data.client.disconnect()
    return unload_ok
