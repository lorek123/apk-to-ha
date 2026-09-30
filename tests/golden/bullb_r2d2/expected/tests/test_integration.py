# SPDX-License-Identifier: MIT
"""Runtime tests for Build Your Own R2-D2: config flow, push updates, reconnect, unload."""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import timedelta

from custom_components.r2d2.const import DOMAIN
from custom_components.r2d2.coordinator import RECONNECT_INTERVAL
from homeassistant.config_entries import SOURCE_USER, ConfigEntryState
from homeassistant.const import (
    ATTR_ASSUMED_STATE,
    ATTR_ENTITY_ID,
    CONF_HOST,
    CONF_PORT,
    STATE_UNAVAILABLE,
    EntityCategory,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from .conftest import AUTH_CMD, MockDevice

HOST = "127.0.0.1"
PROBE_PLATFORM = "sensor"
PROBE_KEY = "battery"


async def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    """Wait for socket-driven state changes that async_block_till_done can't see."""
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


def _probe_entity_id(hass: HomeAssistant, entry: MockConfigEntry) -> str:
    return _entity_id(hass, entry, PROBE_PLATFORM, PROBE_KEY)


def _sent(device: MockDevice, **expected: object) -> bool:
    return any(all(m.get(k) == v for k, v in expected.items()) for m in device.received)


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
    # The flow's validation and the entry setup pair with the same identity.
    uuids = {m.get("uuid") for m in mock_device.received if m.get("cmd") == AUTH_CMD}
    assert len(uuids) == 1


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


async def test_push_updates_entity(hass: HomeAssistant, mock_device: MockDevice) -> None:
    entry = await _setup_entry(hass, mock_device.port)
    assert entry.state is ConfigEntryState.LOADED
    entity_id = _probe_entity_id(hass, entry)
    assert hass.states.get(entity_id).state == "1"

    await mock_device.push(**{PROBE_KEY: 2})
    await _wait_for(lambda: hass.states.get(entity_id).state == "2")


async def test_disconnect_marks_unavailable_then_reconnects(
    hass: HomeAssistant, mock_device: MockDevice
) -> None:
    entry = await _setup_entry(hass, mock_device.port)
    entity_id = _probe_entity_id(hass, entry)
    port = mock_device.port

    await mock_device.stop()
    await _wait_for(lambda: hass.states.get(entity_id).state == STATE_UNAVAILABLE)

    await mock_device.start(port)
    async_fire_time_changed(hass, dt_util.utcnow() + RECONNECT_INTERVAL + timedelta(seconds=1))
    await _wait_for(lambda: hass.states.get(entity_id).state != STATE_UNAVAILABLE)


async def test_unload_disconnects(hass: HomeAssistant, mock_device: MockDevice) -> None:
    entry = await _setup_entry(hass, mock_device.port)
    assert mock_device.connected_clients == 1

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.NOT_LOADED
    await _wait_for(lambda: mock_device.connected_clients == 0)


async def test_switch_sends_enable(hass: HomeAssistant, mock_device: MockDevice) -> None:
    entry = await _setup_entry(hass, mock_device.port)
    entity_id = _entity_id(hass, entry, "switch", "power")

    await hass.services.async_call(
        "switch", "turn_on", {ATTR_ENTITY_ID: entity_id}, blocking=True
    )
    await _wait_for(lambda: _sent(mock_device, cmd="power", enable=True))
    # No state field for this switch in the protocol: HA must know it's optimistic.
    state = hass.states.get(entity_id)
    assert state.attributes.get(ATTR_ASSUMED_STATE) is True
    assert state.state == "on"


async def test_select_follows_pushed_mode(hass: HomeAssistant, mock_device: MockDevice) -> None:
    entry = await _setup_entry(hass, mock_device.port)
    entity_id = _entity_id(hass, entry, "select", "mode")

    await mock_device.push(**{"mode": 2})
    await _wait_for(lambda: hass.states.get(entity_id).state == "turn_around")

    await hass.services.async_call(
        "select",
        "select_option",
        {ATTR_ENTITY_ID: entity_id, "option": "play"},
        blocking=True,
    )
    await _wait_for(lambda: _sent(mock_device, cmd="mode"))


async def test_maintenance_buttons_hidden_by_default(
    hass: HomeAssistant, mock_device: MockDevice
) -> None:
    entry = await _setup_entry(hass, mock_device.port)
    registry = er.async_get(hass)
    for key in ["reset_mcu", "d_head_power", "d_leg_power"]:
        entity = registry.async_get(_entity_id(hass, entry, "button", key))
        assert entity is not None
        assert entity.disabled_by is er.RegistryEntryDisabler.INTEGRATION, key
        assert entity.entity_category is EntityCategory.CONFIG, key
