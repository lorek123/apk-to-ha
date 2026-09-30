# SPDX-License-Identifier: MIT
"""Actions for Inkcast: device commands that take parameters or return a reply."""
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
from inkcast_sdk import InkcastClient, InkcastConnectionError

from .const import DOMAIN

_SCHEMA_DOWNLOAD = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("path"): cv.string,
    }
)

_SCHEMA_FILES = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("path"): cv.string,
    }
)

_SCHEMA_GET_SETTINGS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_POST_SETTINGS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("body"): dict,
    }
)

_SCHEMA_DELETE = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("path"): cv.string,
        vol.Required("type"): cv.string,
    }
)

_SCHEMA_RENAME = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("path"): cv.string,
        vol.Required("name"): cv.string,
    }
)

_SCHEMA_MOVE = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("path"): cv.string,
        vol.Required("dest"): cv.string,
    }
)

_SCHEMA_MKDIR = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("name"): cv.string,
        vol.Required("path"): cv.string,
    }
)


def _client(call: ServiceCall) -> InkcastClient:
    """The client of the loaded config entry the action targets."""
    entry = call.hass.config_entries.async_get_entry(call.data[ATTR_CONFIG_ENTRY_ID])
    if entry is None or entry.domain != DOMAIN:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_found")
    if entry.state is not ConfigEntryState.LOADED:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_loaded")
    client: InkcastClient = entry.runtime_data.client
    return client


def _failed(action: str, err: Exception) -> HomeAssistantError:
    return HomeAssistantError(
        translation_domain=DOMAIN,
        translation_key="action_failed",
        translation_placeholders={"action": action, "error": str(err)},
    )


async def _download(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.download(
            path=call.data["path"],
        )
    except InkcastConnectionError as err:
        raise _failed("download", err) from err
    return reply


async def _files(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.files(
            path=call.data["path"],
        )
    except InkcastConnectionError as err:
        raise _failed("files", err) from err
    return reply


async def _get_settings(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_settings()
    except InkcastConnectionError as err:
        raise _failed("get_settings", err) from err
    return reply


async def _post_settings(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.post_settings(
            body=call.data["body"],
        )
    except InkcastConnectionError as err:
        raise _failed("post_settings", err) from err
    return None


async def _delete(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.delete(
            path=call.data["path"],
            type=call.data["type"],
        )
    except InkcastConnectionError as err:
        raise _failed("delete", err) from err
    return None


async def _rename(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.rename(
            path=call.data["path"],
            name=call.data["name"],
        )
    except InkcastConnectionError as err:
        raise _failed("rename", err) from err
    return None


async def _move(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.move(
            path=call.data["path"],
            dest=call.data["dest"],
        )
    except InkcastConnectionError as err:
        raise _failed("move", err) from err
    return None


async def _mkdir(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.mkdir(
            name=call.data["name"],
            path=call.data["path"],
        )
    except InkcastConnectionError as err:
        raise _failed("mkdir", err) from err
    return None


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the actions once per Home Assistant instance (not per entry)."""
    hass.services.async_register(
        DOMAIN,
        "download",
        _download,
        schema=_SCHEMA_DOWNLOAD,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "files",
        _files,
        schema=_SCHEMA_FILES,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "get_settings",
        _get_settings,
        schema=_SCHEMA_GET_SETTINGS,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "post_settings",
        _post_settings,
        schema=_SCHEMA_POST_SETTINGS,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "delete",
        _delete,
        schema=_SCHEMA_DELETE,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "rename",
        _rename,
        schema=_SCHEMA_RENAME,
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
        "mkdir",
        _mkdir,
        schema=_SCHEMA_MKDIR,
        supports_response=SupportsResponse.NONE,
    )
