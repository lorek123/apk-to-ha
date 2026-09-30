# SPDX-License-Identifier: MIT
"""Actions for NOVA: device commands that take parameters or return a reply."""
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
from nova_sdk import NovaClient, NovaConnectionError

from .const import DOMAIN

_SCHEMA_UPDATE_CONTAINER = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_REBOOT_VM = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_GET_PLUGIN_OPERATIONS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_ARCHIVE_NOTIFICATION = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_PAUSE_CONTAINER = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_GET_NOTIFICATIONS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_PAUSE_VM = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_GET_NETWORK_THROUGHPUT = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_STOP_VM = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_DELETE_NOTIFICATION = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
        vol.Required("type"): cv.string,
    }
)

_SCHEMA_UNREAD_NOTIFICATION = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_START_CONTAINER = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_GET_DOCKER_CONTAINERS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_START_VM = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_START_PARITY_CHECK = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("correct"): cv.boolean,
    }
)

_SCHEMA_PING = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_GET_INSTALLED_UNRAID_PLUGINS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_FORCE_STOP_VM = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_GET_PLUGINS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_FETCH_CONTAINER_LOGS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
        vol.Optional("tail"): vol.Coerce(int),
    }
)

_SCHEMA_GET_NETWORK_INTERFACES = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)

_SCHEMA_RESUME_VM = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_STOP_CONTAINER = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_UNPAUSE_CONTAINER = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_RESET_VM = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
        vol.Required("id"): cv.string,
    }
)

_SCHEMA_GET_VMS = vol.Schema(
    {
        vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string,
    }
)


def _client(call: ServiceCall) -> NovaClient:
    """The client of the loaded config entry the action targets."""
    entry = call.hass.config_entries.async_get_entry(call.data[ATTR_CONFIG_ENTRY_ID])
    if entry is None or entry.domain != DOMAIN:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_found")
    if entry.state is not ConfigEntryState.LOADED:
        raise ServiceValidationError(translation_domain=DOMAIN, translation_key="entry_not_loaded")
    client: NovaClient = entry.runtime_data.client
    return client


def _failed(action: str, err: Exception) -> HomeAssistantError:
    return HomeAssistantError(
        translation_domain=DOMAIN,
        translation_key="action_failed",
        translation_placeholders={"action": action, "error": str(err)},
    )


async def _update_container(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.update_container(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("update_container", err) from err
    return None


async def _reboot_vm(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.reboot_vm(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("reboot_vm", err) from err
    return None


async def _get_plugin_operations(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_plugin_operations()
    except NovaConnectionError as err:
        raise _failed("get_plugin_operations", err) from err
    return reply


async def _archive_notification(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.archive_notification(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("archive_notification", err) from err
    return None


async def _pause_container(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.pause_container(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("pause_container", err) from err
    return None


async def _get_notifications(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_notifications()
    except NovaConnectionError as err:
        raise _failed("get_notifications", err) from err
    return reply


async def _pause_vm(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.pause_vm(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("pause_vm", err) from err
    return None


async def _get_network_throughput(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_network_throughput()
    except NovaConnectionError as err:
        raise _failed("get_network_throughput", err) from err
    return reply


async def _stop_vm(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.stop_vm(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("stop_vm", err) from err
    return None


async def _delete_notification(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.delete_notification(
            id=call.data["id"],
            type=call.data["type"],
        )
    except NovaConnectionError as err:
        raise _failed("delete_notification", err) from err
    return None


async def _unread_notification(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.unread_notification(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("unread_notification", err) from err
    return None


async def _start_container(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.start_container(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("start_container", err) from err
    return None


async def _get_docker_containers(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_docker_containers()
    except NovaConnectionError as err:
        raise _failed("get_docker_containers", err) from err
    return reply


async def _start_vm(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.start_vm(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("start_vm", err) from err
    return None


async def _start_parity_check(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.start_parity_check(
            correct=call.data["correct"],
        )
    except NovaConnectionError as err:
        raise _failed("start_parity_check", err) from err
    return None


async def _ping(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.ping()
    except NovaConnectionError as err:
        raise _failed("ping", err) from err
    return reply


async def _get_installed_unraid_plugins(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_installed_unraid_plugins()
    except NovaConnectionError as err:
        raise _failed("get_installed_unraid_plugins", err) from err
    return reply


async def _force_stop_vm(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.force_stop_vm(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("force_stop_vm", err) from err
    return None


async def _get_plugins(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_plugins()
    except NovaConnectionError as err:
        raise _failed("get_plugins", err) from err
    return reply


async def _fetch_container_logs(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.fetch_container_logs(
            id=call.data["id"],
            tail=call.data.get("tail"),
        )
    except NovaConnectionError as err:
        raise _failed("fetch_container_logs", err) from err
    return reply


async def _get_network_interfaces(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_network_interfaces()
    except NovaConnectionError as err:
        raise _failed("get_network_interfaces", err) from err
    return reply


async def _resume_vm(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.resume_vm(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("resume_vm", err) from err
    return None


async def _stop_container(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.stop_container(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("stop_container", err) from err
    return None


async def _unpause_container(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.unpause_container(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("unpause_container", err) from err
    return None


async def _reset_vm(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        await client.reset_vm(
            id=call.data["id"],
        )
    except NovaConnectionError as err:
        raise _failed("reset_vm", err) from err
    return None


async def _get_vms(call: ServiceCall) -> ServiceResponse:
    client = _client(call)
    try:
        reply: dict[str, Any] = await client.get_vms()
    except NovaConnectionError as err:
        raise _failed("get_vms", err) from err
    return reply


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    """Register the actions once per Home Assistant instance (not per entry)."""
    hass.services.async_register(
        DOMAIN,
        "update_container",
        _update_container,
        schema=_SCHEMA_UPDATE_CONTAINER,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "reboot_vm",
        _reboot_vm,
        schema=_SCHEMA_REBOOT_VM,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "get_plugin_operations",
        _get_plugin_operations,
        schema=_SCHEMA_GET_PLUGIN_OPERATIONS,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "archive_notification",
        _archive_notification,
        schema=_SCHEMA_ARCHIVE_NOTIFICATION,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "pause_container",
        _pause_container,
        schema=_SCHEMA_PAUSE_CONTAINER,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "get_notifications",
        _get_notifications,
        schema=_SCHEMA_GET_NOTIFICATIONS,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "pause_vm",
        _pause_vm,
        schema=_SCHEMA_PAUSE_VM,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "get_network_throughput",
        _get_network_throughput,
        schema=_SCHEMA_GET_NETWORK_THROUGHPUT,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "stop_vm",
        _stop_vm,
        schema=_SCHEMA_STOP_VM,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "delete_notification",
        _delete_notification,
        schema=_SCHEMA_DELETE_NOTIFICATION,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "unread_notification",
        _unread_notification,
        schema=_SCHEMA_UNREAD_NOTIFICATION,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "start_container",
        _start_container,
        schema=_SCHEMA_START_CONTAINER,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "get_docker_containers",
        _get_docker_containers,
        schema=_SCHEMA_GET_DOCKER_CONTAINERS,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "start_vm",
        _start_vm,
        schema=_SCHEMA_START_VM,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "start_parity_check",
        _start_parity_check,
        schema=_SCHEMA_START_PARITY_CHECK,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "ping",
        _ping,
        schema=_SCHEMA_PING,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "get_installed_unraid_plugins",
        _get_installed_unraid_plugins,
        schema=_SCHEMA_GET_INSTALLED_UNRAID_PLUGINS,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "force_stop_vm",
        _force_stop_vm,
        schema=_SCHEMA_FORCE_STOP_VM,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "get_plugins",
        _get_plugins,
        schema=_SCHEMA_GET_PLUGINS,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "fetch_container_logs",
        _fetch_container_logs,
        schema=_SCHEMA_FETCH_CONTAINER_LOGS,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "get_network_interfaces",
        _get_network_interfaces,
        schema=_SCHEMA_GET_NETWORK_INTERFACES,
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "resume_vm",
        _resume_vm,
        schema=_SCHEMA_RESUME_VM,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "stop_container",
        _stop_container,
        schema=_SCHEMA_STOP_CONTAINER,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "unpause_container",
        _unpause_container,
        schema=_SCHEMA_UNPAUSE_CONTAINER,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "reset_vm",
        _reset_vm,
        schema=_SCHEMA_RESET_VM,
        supports_response=SupportsResponse.NONE,
    )
    hass.services.async_register(
        DOMAIN,
        "get_vms",
        _get_vms,
        schema=_SCHEMA_GET_VMS,
        supports_response=SupportsResponse.ONLY,
    )
