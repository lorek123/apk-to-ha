# SPDX-License-Identifier: MIT
"""Runtime tests for NOVA: config flow, polling, mutations, reauth, unload."""
from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from custom_components.nova.const import DOMAIN
from custom_components.nova.coordinator import POLL_INTERVAL
from homeassistant.config_entries import SOURCE_USER, ConfigEntryState
from homeassistant.const import (
    ATTR_CONFIG_ENTRY_ID,
    ATTR_ENTITY_ID,
    CONF_API_KEY,
    CONF_URL,
    CONF_VERIFY_SSL,
    STATE_UNAVAILABLE,
    EntityCategory,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from .conftest import API_KEY, MockServer

PROBE_PLATFORM = "sensor"
PROBE_KEY = "array.capacity.kilobytes.free"


def _data(server: MockServer, api_key: str = API_KEY) -> dict:
    return {
        CONF_URL: server.url,
        CONF_API_KEY: api_key,
        CONF_VERIFY_SSL: False,
    }


async def _setup_entry(hass: HomeAssistant, server: MockServer) -> MockConfigEntry:
    entry = MockConfigEntry(domain=DOMAIN, unique_id="127.0.0.1", data=_data(server))
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _entity_id(hass: HomeAssistant, entry: MockConfigEntry, platform: str, key: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id(platform, DOMAIN, f"{entry.entry_id}_{key}")
    assert entity_id is not None, f"no {platform} entity for {key}"
    return entity_id


async def _poll(hass: HomeAssistant) -> None:
    async_fire_time_changed(hass, dt_util.utcnow() + POLL_INTERVAL + timedelta(seconds=1))
    await hass.async_block_till_done(wait_background_tasks=True)


async def test_user_flow_creates_entry(hass: HomeAssistant, server: MockServer) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(result["flow_id"], _data(server))
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "127.0.0.1"
    assert result["result"].state is ConfigEntryState.LOADED


async def test_user_flow_rejects_wrong_key(hass: HomeAssistant, server: MockServer) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], _data(server, api_key="wrong")
    )

    assert result["errors"] == {"base": "invalid_auth"}
    assert "wrong" not in str(result.get("data_schema"))  # the key isn't echoed back


async def test_user_flow_cannot_connect(hass: HomeAssistant, unused_tcp_port: int) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_URL: f"http://127.0.0.1:{unused_tcp_port}", CONF_API_KEY: API_KEY, CONF_VERIFY_SSL: False},
    )

    assert result["errors"] == {"base": "cannot_connect"}


async def test_poll_updates_entity(hass: HomeAssistant, server: MockServer) -> None:
    entry = await _setup_entry(hass, server)
    entity_id = _entity_id(hass, entry, PROBE_PLATFORM, PROBE_KEY)
    assert hass.states.get(entity_id).state == "1"

    server.set_state(**{PROBE_KEY: 2})
    await _poll(hass)

    assert hass.states.get(entity_id).state == "2"


async def test_unavailable_while_down_then_recovers(
    hass: HomeAssistant, server: MockServer
) -> None:
    entry = await _setup_entry(hass, server)
    entity_id = _entity_id(hass, entry, PROBE_PLATFORM, PROBE_KEY)
    port = server.port

    await server.stop()
    await _poll(hass)
    assert hass.states.get(entity_id).state == STATE_UNAVAILABLE

    await server.start(port)
    await _poll(hass)
    assert hass.states.get(entity_id).state != STATE_UNAVAILABLE


async def test_button_runs_mutation(hass: HomeAssistant, server: MockServer) -> None:
    entry = await _setup_entry(hass, server)
    entity_id = _entity_id(hass, entry, "button", "resume_parity_check")

    await hass.services.async_call("button", "press", {ATTR_ENTITY_ID: entity_id}, blocking=True)

    assert server.mutations == ["ResumeParityCheck"]


async def test_revoked_key_starts_reauth(hass: HomeAssistant, server: MockServer) -> None:
    entry = await _setup_entry(hass, server)
    server.api_key = "rotated"

    await _poll(hass)

    flows = hass.config_entries.flow.async_progress_by_handler(DOMAIN)
    assert [f["context"]["source"] for f in flows] == ["reauth"]
    result = await hass.config_entries.flow.async_configure(
        flows[0]["flow_id"], {CONF_API_KEY: "rotated"}
    )
    assert result["type"] is FlowResultType.ABORT and result["reason"] == "reauth_successful"
    assert entry.data[CONF_API_KEY] == "rotated"


async def test_maintenance_buttons_hidden_by_default(
    hass: HomeAssistant, server: MockServer
) -> None:
    entry = await _setup_entry(hass, server)
    registry = er.async_get(hass)
    for key in ["stop_array", "delete_archived_notifications", "update_all_containers"]:
        entity = registry.async_get(_entity_id(hass, entry, "button", key))
        assert entity is not None
        assert entity.disabled_by is er.RegistryEntryDisabler.INTEGRATION, key
        assert entity.entity_category is EntityCategory.CONFIG, key


async def test_unload(hass: HomeAssistant, server: MockServer) -> None:
    entry = await _setup_entry(hass, server)

    assert await hass.config_entries.async_unload(entry.entry_id)
    assert entry.state is ConfigEntryState.NOT_LOADED


ACTION_DATA: dict[str, Any] = json.loads("{\"id\": \"test\", \"type\": \"test\"}")


async def test_action_sends_command(hass: HomeAssistant, server: MockServer) -> None:
    """The delete_notification action sends MUTATION DeleteNotification with its parameters."""
    entry = await _setup_entry(hass, server)
    await hass.services.async_call(
        DOMAIN,
        "delete_notification",
        {ATTR_CONFIG_ENTRY_ID: entry.entry_id, **ACTION_DATA},
        blocking=True,
    )
    assert server.mutations[-1] == "DeleteNotification"
    assert server.variables[-1] == json.loads("{\"id\": \"test\", \"type\": \"test\"}")


async def test_action_needs_loaded_entry(hass: HomeAssistant, server: MockServer) -> None:
    """Actions are registered once; on an unloaded entry they refuse, not crash."""
    entry = await _setup_entry(hass, server)
    await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(
            DOMAIN,
            "delete_notification",
            {ATTR_CONFIG_ENTRY_ID: entry.entry_id, **ACTION_DATA},
            blocking=True,
        )


async def test_query_action_returns_reply(hass: HomeAssistant, server: MockServer) -> None:
    """The get_plugin_operations action returns the device's reply."""
    entry = await _setup_entry(hass, server)
    response = await hass.services.async_call(
        DOMAIN,
        "get_plugin_operations",
        {
            ATTR_CONFIG_ENTRY_ID: entry.entry_id,
            **json.loads("{}"),
        },
        blocking=True,
        return_response=True,
    )
    assert response == json.loads("{\"GetPluginOperations\": true}")
