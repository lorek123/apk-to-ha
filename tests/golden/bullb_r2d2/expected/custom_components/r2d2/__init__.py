# SPDX-License-Identifier: MIT
"""Build Your Own R2-D2 Home Assistant integration."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType
from r2d2_sdk import R2D2Client

from .const import DEFAULT_PORT, DOMAIN
from .coordinator import R2D2Coordinator
from .services import async_setup_services

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.SWITCH,
    Platform.BUTTON,
    Platform.SELECT,
]


@dataclass
class R2D2RuntimeData:
    coordinator: R2D2Coordinator
    client: R2D2Client


type R2D2ConfigEntry = ConfigEntry[R2D2RuntimeData]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the integration's actions (they target a config entry by ID)."""
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: R2D2ConfigEntry) -> bool:
    session = aiohttp_client.async_get_clientsession(hass)
    client = R2D2Client(
        host=entry.data[CONF_HOST],
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        session=session,
    )
    coordinator = R2D2Coordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = R2D2RuntimeData(coordinator=coordinator, client=client)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: R2D2ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        await entry.runtime_data.client.disconnect()
    return unload_ok
