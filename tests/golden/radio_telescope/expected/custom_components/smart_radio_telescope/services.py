# SPDX-License-Identifier: MIT
"""Actions for Smart Radio Telescope: device commands that take parameters or return a reply."""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import ATTR_CONFIG_ENTRY_ID
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from smart_radio_telescope_sdk import SmartRadioTelescopeClient, SmartRadioTelescopeConnectionError

from .const import DOMAIN

_SCHEMA_SYSTEM = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_GOTO = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("az"): vol.Coerce(float),
        vol.Required("el"): vol.Coerce(float),
        vol.Required("pol"): vol.Coerce(float),
    }
)

_SCHEMA_GOTO_RADEC = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("ra_deg"): vol.Coerce(float),
        vol.Required("dec_deg"): vol.Coerce(float),
        vol.Required("lat"): vol.Coerce(float),
        vol.Required("lon"): vol.Coerce(float),
    }
)

_SCHEMA_HOME = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("axis"): cv.string,
    }
)

_SCHEMA_MOVE = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("axis"): cv.string,
        vol.Required("degrees"): vol.Coerce(float),
    }
)

_SCHEMA_JOG = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("az_dps"): vol.Coerce(float),
        vol.Required("el_dps"): vol.Coerce(float),
    }
)

_SCHEMA_SCAN = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("sweep"): cv.string,
        vol.Required("pattern"): cv.string,
        vol.Required("s0"): vol.Coerce(float),
        vol.Required("s1"): vol.Coerce(float),
        vol.Required("t0"): vol.Coerce(float),
        vol.Required("t1"): vol.Coerce(float),
        vol.Required("speed"): vol.Coerce(float),
        vol.Required("rows"): vol.Coerce(int),
    }
)


def _client(call: ServiceCall) -> SmartRadioTelescopeClient:
    """The client of the loaded config entry the action targets."""
    entry = call.hass.config_entries.async_get_entry(call.data[ATTR_CONFIG_ENTRY_ID])
    if entry is None or entry.domain != DOMAIN:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_found")
    if entry.state is not ConfigEntryState.LOADED:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_loaded")
    client: SmartRadioTelescopeClient = entry.runtime_data.client
    return client


def _failed(action: str, err: Exception) -> HomeAssistantError:
    return HomeAssistantError(
        translation_domain=DOMAIN,
        translation_key="action_failed",
        translation_placeholders={"action": action, "error": str(err)},
    )


async def _system(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.system()
    except SmartRadioTelescopeConnectionError as err:
        raise _failed("system", err) from err
    return reply


async def _goto(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.goto(
            az=call.data["az"],
            el=call.data["el"],
            pol=call.data["pol"],
        )
    except SmartRadioTelescopeConnectionError as err:
        raise _failed("goto", err) from err
    return None


async def _goto_radec(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.goto_radec(
            ra_deg=call.data["ra_deg"],
            dec_deg=call.data["dec_deg"],
            lat=call.data["lat"],
            lon=call.data["lon"],
        )
    except SmartRadioTelescopeConnectionError as err:
        raise _failed("goto_radec", err) from err
    return None


async def _home(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.home(
            axis=call.data["axis"],
        )
    except SmartRadioTelescopeConnectionError as err:
        raise _failed("home", err) from err
    return None


async def _move(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.move(
            axis=call.data["axis"],
            degrees=call.data["degrees"],
        )
    except SmartRadioTelescopeConnectionError as err:
        raise _failed("move", err) from err
    return None


async def _jog(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.jog(
            az_dps=call.data["az_dps"],
            el_dps=call.data["el_dps"],
        )
    except SmartRadioTelescopeConnectionError as err:
        raise _failed("jog", err) from err
    return None


async def _scan(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.scan(
            sweep=call.data["sweep"],
            pattern=call.data["pattern"],
            s0=call.data["s0"],
            s1=call.data["s1"],
            t0=call.data["t0"],
            t1=call.data["t1"],
            speed=call.data["speed"],
            rows=call.data["rows"],
        )
    except SmartRadioTelescopeConnectionError as err:
        raise _failed("scan", err) from err
    return None


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the actions once per Home Assistant instance (not per entry)."""
    hass.services.async_register(
        DOMAIN,
        "system",
        _system,
        schema=_SCHEMA_SYSTEM,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "goto",
        _goto,
        schema=_SCHEMA_GOTO,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "goto_radec",
        _goto_radec,
        schema=_SCHEMA_GOTO_RADEC,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "home",
        _home,
        schema=_SCHEMA_HOME,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "move",
        _move,
        schema=_SCHEMA_MOVE,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "jog",
        _jog,
        schema=_SCHEMA_JOG,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "scan",
        _scan,
        schema=_SCHEMA_SCAN,
        supports_response=SupportsResponse.NONE,
    )
