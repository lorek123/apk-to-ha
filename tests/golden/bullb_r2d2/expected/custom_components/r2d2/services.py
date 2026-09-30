# SPDX-License-Identifier: MIT
"""Actions for Build Your Own R2-D2: device commands that take parameters or return a reply."""
from __future__ import annotations

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
from r2d2_sdk import R2D2Client, R2D2ConnectionError

from .const import DOMAIN

_SCHEMA_PLAY_SOUND = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("interrupt"): vol.Coerce(int),
        vol.Required("sound_id"): cv.string,
    }
)

_SCHEMA_MOVE_HEAD = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("angle"): cv.string,
    }
)

_SCHEMA_SELF_UPDATE = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("url"): cv.string,
    }
)

_SCHEMA_CHANGE_NAME = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("new_name"): cv.string,
    }
)

_SCHEMA_UNPAIR = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("uuid"): cv.string,
    }
)

_SCHEMA_CONNECT_WIFI = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("ssid"): cv.string,
        vol.Required("wifi_pw"): cv.string,
        vol.Required("enable"): cv.boolean,
    }
)

_SCHEMA_HEAD_SHIFT = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("angle"): vol.Coerce(int),
        vol.Required("interrupt"): vol.Coerce(int),
    }
)

_SCHEMA_MOVE = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("angle"): cv.string,
        vol.Required("enable"): cv.boolean,
    }
)

_SCHEMA_HEAD_DIR = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("dir"): cv.string,
    }
)


def _client(call: ServiceCall) -> R2D2Client:
    """The client of the loaded config entry the action targets."""
    entry = call.hass.config_entries.async_get_entry(call.data[ATTR_CONFIG_ENTRY_ID])
    if entry is None or entry.domain != DOMAIN:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_found")
    if entry.state is not ConfigEntryState.LOADED:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_loaded")
    client: R2D2Client = entry.runtime_data.client
    return client


def _failed(action: str, err: Exception) -> HomeAssistantError:
    return HomeAssistantError(
        translation_domain=DOMAIN,
        translation_key="action_failed",
        translation_placeholders={"action": action, "error": str(err)},
    )


async def _play_sound(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.play_sound(
            interrupt=call.data["interrupt"],
            sound_id=call.data["sound_id"],
        )
    except R2D2ConnectionError as err:
        raise _failed("play_sound", err) from err
    return None


async def _move_head(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.move_head(
            angle=call.data["angle"],
        )
    except R2D2ConnectionError as err:
        raise _failed("move_head", err) from err
    return None


async def _self_update(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.self_update(
            url=call.data["url"],
        )
    except R2D2ConnectionError as err:
        raise _failed("self_update", err) from err
    return None


async def _change_name(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.change_name(
            new_name=call.data["new_name"],
        )
    except R2D2ConnectionError as err:
        raise _failed("change_name", err) from err
    return None


async def _unpair(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.unpair(
            uuid=call.data["uuid"],
        )
    except R2D2ConnectionError as err:
        raise _failed("unpair", err) from err
    return None


async def _connect_wifi(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.connect_wifi(
            ssid=call.data["ssid"],
            wifi_pw=call.data["wifi_pw"],
            enable=call.data["enable"],
        )
    except R2D2ConnectionError as err:
        raise _failed("connect_wifi", err) from err
    return None


async def _head_shift(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.head_shift(
            angle=call.data["angle"],
            interrupt=call.data["interrupt"],
        )
    except R2D2ConnectionError as err:
        raise _failed("head_shift", err) from err
    return None


async def _move(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.move(
            angle=call.data["angle"],
            enable=call.data["enable"],
        )
    except R2D2ConnectionError as err:
        raise _failed("move", err) from err
    return None


async def _head_dir(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.head_dir(
            dir=call.data["dir"],
        )
    except R2D2ConnectionError as err:
        raise _failed("head_dir", err) from err
    return None


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the actions once per Home Assistant instance (not per entry)."""
    hass.services.async_register(
        DOMAIN,
        "play_sound",
        _play_sound,
        schema=_SCHEMA_PLAY_SOUND,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "move_head",
        _move_head,
        schema=_SCHEMA_MOVE_HEAD,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "self_update",
        _self_update,
        schema=_SCHEMA_SELF_UPDATE,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "change_name",
        _change_name,
        schema=_SCHEMA_CHANGE_NAME,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "unpair",
        _unpair,
        schema=_SCHEMA_UNPAIR,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "connect_wifi",
        _connect_wifi,
        schema=_SCHEMA_CONNECT_WIFI,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "head_shift",
        _head_shift,
        schema=_SCHEMA_HEAD_SHIFT,
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
        "head_dir",
        _head_dir,
        schema=_SCHEMA_HEAD_DIR,
        supports_response=SupportsResponse.NONE,
    )
