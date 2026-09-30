# SPDX-License-Identifier: MIT
"""Runtime tests for Inkcast: config flow, polling, availability, commands, unload."""
from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest
from custom_components.inkcast.const import DOMAIN
from custom_components.inkcast.coordinator import POLL_INTERVAL
from homeassistant.config_entries import SOURCE_USER, ConfigEntryState
from homeassistant.const import (
    ATTR_CONFIG_ENTRY_ID,
    CONF_HOST,
    CONF_PORT,
    STATE_UNAVAILABLE,
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

from .conftest import MockDevice

HOST = "127.0.0.1"
PROBE_PLATFORM = "sensor"
PROBE_KEY = "freeHeap"


async def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


async def _setup_entry(hass: HomeAssistant, port: int) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id=HOST, data={CONF_HOST: HOST, CONF_PORT: port}
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _entity_id(hass: HomeAssistant, entry: MockConfigEntry, platform: str, key: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id(platform, DOMAIN, f"{entry.entry_id}_{key}")
    assert entity_id is not None, f"no {platform} entity for {key}"
    return entity_id


async def _poll(hass: HomeAssistant) -> None:
    """Advance time past POLL_INTERVAL; the timed refresh runs as a background task."""
    async_fire_time_changed(hass, dt_util.utcnow() + POLL_INTERVAL + timedelta(seconds=1))
    await hass.async_block_till_done(wait_background_tasks=True)


async def test_user_flow_creates_entry(hass: HomeAssistant, mock_device: MockDevice) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: HOST, CONF_PORT: mock_device.port}
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == HOST
    assert result["result"].state is ConfigEntryState.LOADED


async def test_user_flow_cannot_connect(hass: HomeAssistant, unused_tcp_port: int) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: HOST, CONF_PORT: unused_tcp_port}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_connect"}


async def test_setup_retries_when_unreachable(hass: HomeAssistant, unused_tcp_port: int) -> None:
    entry = await _setup_entry(hass, unused_tcp_port)

    assert entry.state is ConfigEntryState.SETUP_RETRY


async def test_poll_updates_entity(hass: HomeAssistant, mock_device: MockDevice) -> None:
    entry = await _setup_entry(hass, mock_device.port)
    entity_id = _entity_id(hass, entry, PROBE_PLATFORM, PROBE_KEY)
    assert hass.states.get(entity_id).state == "1"

    mock_device.set_state(**{PROBE_KEY: 2})
    await _poll(hass)

    assert hass.states.get(entity_id).state == "2"


async def test_unavailable_while_down_then_recovers(
    hass: HomeAssistant, mock_device: MockDevice
) -> None:
    entry = await _setup_entry(hass, mock_device.port)
    entity_id = _entity_id(hass, entry, PROBE_PLATFORM, PROBE_KEY)
    port = mock_device.port

    await mock_device.stop()
    await _poll(hass)
    assert hass.states.get(entity_id).state == STATE_UNAVAILABLE

    await mock_device.start(port)
    await _poll(hass)
    assert hass.states.get(entity_id).state != STATE_UNAVAILABLE


async def test_unload(hass: HomeAssistant, mock_device: MockDevice) -> None:
    entry = await _setup_entry(hass, mock_device.port)

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.NOT_LOADED


ACTION_DATA: dict[str, Any] = json.loads("{\"path\": \"test\", \"type\": \"test\"}")


async def test_action_sends_command(hass: HomeAssistant, mock_device: MockDevice) -> None:
    """The delete action sends POST /delete with its parameters."""
    entry = await _setup_entry(hass, mock_device.port)
    await hass.services.async_call(
        DOMAIN,
        "delete",
        {ATTR_CONFIG_ENTRY_ID: entry.entry_id, **ACTION_DATA},
        blocking=True,
    )
    method, path, body = mock_device.requests[-1]
    assert (method, path) == (
        "POST",
        "/delete",
    )
    assert body == json.loads("{\"path\": \"test\", \"type\": \"test\"}")
    assert mock_device.queries[-1] == json.loads("{}")


async def test_action_needs_loaded_entry(hass: HomeAssistant, mock_device: MockDevice) -> None:
    """Actions are registered once; on an unloaded entry they refuse, not crash."""
    entry = await _setup_entry(hass, mock_device.port)
    await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    with pytest.raises(ServiceValidationError):
        await hass.services.async_call(
            DOMAIN,
            "delete",
            {ATTR_CONFIG_ENTRY_ID: entry.entry_id, **ACTION_DATA},
            blocking=True,
        )


async def test_query_action_returns_reply(hass: HomeAssistant, mock_device: MockDevice) -> None:
    """The download action returns the device's reply."""
    entry = await _setup_entry(hass, mock_device.port)
    response = await hass.services.async_call(
        DOMAIN,
        "download",
        {
            ATTR_CONFIG_ENTRY_ID: entry.entry_id,
            **json.loads("{\"path\": \"test\"}"),
        },
        blocking=True,
        return_response=True,
    )
    assert response == {"ok": True}
