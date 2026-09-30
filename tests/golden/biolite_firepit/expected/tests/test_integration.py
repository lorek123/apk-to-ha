# SPDX-License-Identifier: MIT
"""Runtime tests for Firepit: discovery, config flow, state, controls, availability."""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from custom_components.firepit.const import DOMAIN, POLL_INTERVAL
from firepit_sdk import client as sdk_client
from homeassistant.config_entries import SOURCE_BLUETOOTH, SOURCE_USER, ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID, CONF_ADDRESS, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from .conftest import ADDRESS, NAME, FakeDevice


async def _setup(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id=ADDRESS, title=NAME, data={CONF_ADDRESS: ADDRESS}
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _entity_id(hass: HomeAssistant, platform: str, key: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id(platform, DOMAIN, f"{ADDRESS}_{key}")
    assert entity_id is not None, f"no {platform} entity for {key}"
    return entity_id


async def _poll(hass: HomeAssistant) -> None:
    async_fire_time_changed(hass, dt_util.utcnow() + POLL_INTERVAL + timedelta(seconds=1))
    await hass.async_block_till_done(wait_background_tasks=True)


async def test_user_flow_creates_entry(hass: HomeAssistant, device: FakeDevice) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM and result["step_id"] == "user"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ADDRESS: ADDRESS}
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == NAME
    assert result["result"].unique_id == ADDRESS


async def test_user_flow_cannot_connect(hass: HomeAssistant, device: FakeDevice) -> None:
    device.reachable = False
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ADDRESS: ADDRESS}
    )

    assert result["errors"] == {"base": "cannot_connect"}


async def test_bluetooth_discovery_confirms(hass: HomeAssistant, device: FakeDevice) -> None:
    info = SimpleNamespace(
        address=ADDRESS, name=NAME, service_uuids=list(sdk_client.SERVICE_UUIDS)
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=info
    )
    assert result["step_id"] == "bluetooth_confirm"

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_discovery_ignores_other_devices(hass: HomeAssistant, device: FakeDevice) -> None:
    info = SimpleNamespace(address="11:22:33:44:55:66", name="Something else", service_uuids=[])
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=info
    )

    assert result["type"] is FlowResultType.ABORT and result["reason"] == "not_supported"


async def test_entities_show_device_state(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)

    assert hass.states.get(_entity_id(hass, "sensor", "battery_level")).state == "80"
    assert hass.states.get(_entity_id(hass, "sensor", "led_status")).state == "7"
    assert hass.states.get(_entity_id(hass, "sensor", "battery_current")).state == "300"
    assert hass.states.get(_entity_id(hass, "sensor", "temperature")).state == "7"
    assert hass.states.get(_entity_id(hass, "binary_sensor", "usb_output_control")).state == "on"
    assert hass.states.get(_entity_id(hass, "switch", "usb_charge_out")).state == "on"
    assert hass.states.get(_entity_id(hass, "fan", "fan_speed")).state == "on"
    fan = hass.states.get(_entity_id(hass, "fan", "fan_speed"))
    assert fan.attributes["percentage"] == 50
    entity_entry = er.async_get(hass).async_get(_entity_id(hass, "sensor", "battery_level"))
    assert entity_entry is not None and entity_entry.device_id is not None
    device_entry = dr.async_get(hass).async_get(entity_entry.device_id)
    assert device_entry is not None
    assert device_entry.manufacturer == "Test"


async def test_fan_speed_fan_writes_levels(hass: HomeAssistant, device: FakeDevice) -> None:
    """Percentages map onto the app's levels 1..4; off writes 0."""
    await _setup(hass)
    entity_id = _entity_id(hass, "fan", "fan_speed")

    await hass.services.async_call(
        "fan", "set_percentage", {ATTR_ENTITY_ID: entity_id, "percentage": 100}, blocking=True
    )
    assert device.writes[-1] == (sdk_client.FAN_SPEED_UUID, bytes([4]))
    assert hass.states.get(entity_id).attributes["percentage"] == 100

    await hass.services.async_call("fan", "turn_off", {ATTR_ENTITY_ID: entity_id}, blocking=True)
    assert device.writes[-1] == (sdk_client.FAN_SPEED_UUID, b"\x00")
    assert hass.states.get(entity_id).state == "off"

    # turn_on without a speed resumes the last one
    await hass.services.async_call("fan", "turn_on", {ATTR_ENTITY_ID: entity_id}, blocking=True)
    assert device.writes[-1] == (sdk_client.FAN_SPEED_UUID, bytes([4]))

    # a change made on the device itself shows up on the next poll
    device.values[sdk_client.FAN_SPEED_UUID] = b"\x01"
    await _poll(hass)
    assert hass.states.get(entity_id).attributes["percentage"] == 25


async def test_usb_charge_out_switch_writes(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)
    entity_id = _entity_id(hass, "switch", "usb_charge_out")

    await hass.services.async_call("switch", "turn_off", {ATTR_ENTITY_ID: entity_id}, blocking=True)
    assert device.writes[-1] == (sdk_client.USB_CHARGE_OUT_UUID, b"\x00")
    assert hass.states.get(entity_id).state == "off"

    await hass.services.async_call("switch", "turn_on", {ATTR_ENTITY_ID: entity_id}, blocking=True)
    assert device.writes[-1] == (sdk_client.USB_CHARGE_OUT_UUID, b"\x01")


async def test_unavailable_while_out_of_range_then_recovers(
    hass: HomeAssistant, device: FakeDevice
) -> None:
    await _setup(hass)
    entity_id = _entity_id(hass, "sensor", "battery_level")

    device.reachable = False
    await _poll(hass)
    assert hass.states.get(entity_id).state == STATE_UNAVAILABLE

    device.reachable = True
    await _poll(hass)
    assert hass.states.get(entity_id).state == "80"


async def test_write_out_of_range_raises(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)
    entity_id = _entity_id(hass, "fan", "fan_speed")
    device.reachable = False

    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            "fan", "turn_off", {ATTR_ENTITY_ID: entity_id}, blocking=True
        )


async def test_setup_retries_when_out_of_range(hass: HomeAssistant, device: FakeDevice) -> None:
    device.reachable = False
    entry = await _setup(hass)

    assert entry.state is ConfigEntryState.SETUP_RETRY


async def test_unload(hass: HomeAssistant, device: FakeDevice) -> None:
    entry = await _setup(hass)
    assert entry.state is ConfigEntryState.LOADED

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.NOT_LOADED
