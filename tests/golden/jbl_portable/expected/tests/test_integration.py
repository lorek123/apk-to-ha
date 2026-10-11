# SPDX-License-Identifier: MIT
"""Runtime tests for JBL Portable: discovery, config flow, state, settings, availability."""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from custom_components.jbllink.const import DOMAIN, POLL_INTERVAL
from homeassistant.config_entries import SOURCE_BLUETOOTH, SOURCE_USER, ConfigEntryState
from homeassistant.const import ATTR_ENTITY_ID, CONF_ADDRESS, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from jbllink_sdk import protocol
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from .conftest import (
    ADDRESS,
    ADVERT_NAME,
    CLASSIC_PRODUCT_ID,
    DEVICE_NAME,
    MANUFACTURER_DATA,
    VERSION,
    FakeDevice,
)


async def _setup(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN, unique_id=ADDRESS, title=DEVICE_NAME, data={CONF_ADDRESS: ADDRESS}
    )
    entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


def _entity_id(hass: HomeAssistant, platform: str, key: str) -> str | None:
    return er.async_get(hass).async_get_entity_id(platform, DOMAIN, f"{ADDRESS}_{key}")


def _state(hass: HomeAssistant, platform: str, key: str) -> str:
    entity_id = _entity_id(hass, platform, key)
    assert entity_id is not None, f"no {platform} entity for {key}"
    state = hass.states.get(entity_id)
    assert state is not None
    return state.state


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
    assert result["title"] == DEVICE_NAME  # the name the device reports
    assert result["result"].unique_id == ADDRESS


async def test_user_flow_cannot_connect(hass: HomeAssistant, device: FakeDevice) -> None:
    device.reachable = False
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ADDRESS: ADDRESS}
    )

    assert result["errors"] == {"base": "cannot_connect"}


async def test_bluetooth_discovery_confirms(hass: HomeAssistant, device: FakeDevice) -> None:
    info = SimpleNamespace(address=ADDRESS, name=ADVERT_NAME, manufacturer_data=MANUFACTURER_DATA)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=info
    )
    assert result["step_id"] == "bluetooth_confirm"

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_discovery_ignores_other_devices(hass: HomeAssistant, device: FakeDevice) -> None:
    info = SimpleNamespace(address="11:22:33:44:55:66", name="Other", manufacturer_data={76: b""})
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_BLUETOOTH}, data=info
    )

    assert result["type"] is FlowResultType.ABORT and result["reason"] == "not_supported"


@pytest.mark.skipif(CLASSIC_PRODUCT_ID is None, reason="every known model is Bluetooth LE")
async def test_classic_bluetooth_model_is_refused(
    hass: HomeAssistant, device: FakeDevice
) -> None:
    assert CLASSIC_PRODUCT_ID is not None
    device.product_id = CLASSIC_PRODUCT_ID
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_ADDRESS: ADDRESS}
    )

    assert result["type"] is FlowResultType.ABORT and result["reason"] == "unsupported_model"


async def test_entities_show_device_state(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)

    assert _state(hass, "sensor", "battery") == "80"
    assert _state(hass, "binary_sensor", "charging") == "off"
    assert _state(hass, "switch", "feedback_tone") == "on"
    assert _state(hass, "switch", "hfp") == "on"
    assert _state(hass, "select", "eq_mode") == "indoor"
    assert _state(hass, "select", "mfb") == "play_pause"

    entity_id = _entity_id(hass, "sensor", "battery")
    entity_entry = er.async_get(hass).async_get(entity_id or "")
    assert entity_entry is not None and entity_entry.device_id is not None
    device_entry = dr.async_get(hass).async_get(entity_entry.device_id)
    assert device_entry is not None
    assert device_entry.sw_version == VERSION
    assert device_entry.model == protocol.model(device.product_id)[0]


async def test_charging_shows_on_next_poll(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)

    device.battery = 0x80 | 55
    await _poll(hass)

    assert _state(hass, "sensor", "battery") == "55"
    assert _state(hass, "binary_sensor", "charging") == "on"


async def test_feedback_tone_switch_writes(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)
    entity_id = _entity_id(hass, "switch", "feedback_tone")

    await hass.services.async_call("switch", "turn_off", {ATTR_ENTITY_ID: entity_id}, blocking=True)
    assert device.settings_written()[-1] == (0x67, 0)
    assert _state(hass, "switch", "feedback_tone") == "off"

    await hass.services.async_call("switch", "turn_on", {ATTR_ENTITY_ID: entity_id}, blocking=True)
    assert device.settings_written()[-1] == (0x67, 1)
    assert _state(hass, "switch", "feedback_tone") == "on"


async def test_hfp_switch_writes(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)
    entity_id = _entity_id(hass, "switch", "hfp")

    await hass.services.async_call("switch", "turn_off", {ATTR_ENTITY_ID: entity_id}, blocking=True)
    assert device.settings_written()[-1] == (0x70, 0)
    assert _state(hass, "switch", "hfp") == "off"

    await hass.services.async_call("switch", "turn_on", {ATTR_ENTITY_ID: entity_id}, blocking=True)
    assert device.settings_written()[-1] == (0x70, 1)
    assert _state(hass, "switch", "hfp") == "on"


async def test_eq_mode_select_writes(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)
    entity_id = _entity_id(hass, "select", "eq_mode")

    await hass.services.async_call(
        "select",
        "select_option",
        {ATTR_ENTITY_ID: entity_id, "option": "outdoor"},
        blocking=True,
    )
    assert device.settings_written()[-1] == (0x63, 1)
    assert _state(hass, "select", "eq_mode") == "outdoor"

    # a change made on the device itself shows up on the next poll
    device.values["eq_mode"] = 0
    await _poll(hass)
    assert _state(hass, "select", "eq_mode") == "indoor"


async def test_mfb_select_writes(hass: HomeAssistant, device: FakeDevice) -> None:
    await _setup(hass)
    entity_id = _entity_id(hass, "select", "mfb")

    await hass.services.async_call(
        "select",
        "select_option",
        {ATTR_ENTITY_ID: entity_id, "option": "voice"},
        blocking=True,
    )
    assert device.settings_written()[-1] == (0x32, 1)
    assert _state(hass, "select", "mfb") == "voice"

    # a change made on the device itself shows up on the next poll
    device.values["mfb_status"] = 0
    await _poll(hass)
    assert _state(hass, "select", "mfb") == "play_pause"


async def test_refused_setting_raises(hass: HomeAssistant, device: FakeDevice) -> None:
    """A failure status in the acknowledgement is an error, and the state is kept."""
    await _setup(hass)
    entity_id = _entity_id(hass, "switch", "feedback_tone")
    device.ack_status = protocol.ACK_OK + 1

    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            "switch", "turn_off", {ATTR_ENTITY_ID: entity_id}, blocking=True
        )
    assert _state(hass, "switch", "feedback_tone") == "on"


async def test_model_without_a_feature_gets_no_entity(
    hass: HomeAssistant, device: FakeDevice
) -> None:
    """Models answer subsets of the protocol: nothing is created for silence."""
    del device.values["feedback_tone_status"]
    await _setup(hass)

    assert _entity_id(hass, "switch", "feedback_tone") is None
    assert _state(hass, "sensor", "battery") == "80"


async def test_unavailable_while_out_of_range_then_recovers(
    hass: HomeAssistant, device: FakeDevice
) -> None:
    await _setup(hass)

    device.reachable = False
    await _poll(hass)
    assert _state(hass, "sensor", "battery") == STATE_UNAVAILABLE

    device.reachable = True
    await _poll(hass)
    assert _state(hass, "sensor", "battery") == "80"


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
