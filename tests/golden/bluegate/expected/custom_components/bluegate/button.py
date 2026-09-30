# SPDX-License-Identifier: MIT
"""Button platform for BlueGate: the app's main action, authenticated."""
from __future__ import annotations

from bluegate_sdk import (
    PRIMARY_ACTION,
    BluegateAuthError,
    BluegateConnectionError,
)
from homeassistant.components import bluetooth
from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import BluegateConfigEntry
from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BluegateConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    async_add_entities([BluegateActionButton(entry)])


class BluegateActionButton(ButtonEntity):
    """Runs the device's main action (connects, authenticates, acts, disconnects)."""

    _attr_has_entity_name = True
    _attr_translation_key = "activate"

    def __init__(self, entry: BluegateConfigEntry) -> None:
        self._entry = entry
        address = entry.runtime_data.address
        self._attr_unique_id = f"{address}_action_{PRIMARY_ACTION}"
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, address)},
            identifiers={(DOMAIN, address)},
            name=entry.title,
            manufacturer="BlueGate",
        )

    @property
    def available(self) -> bool:
        return bluetooth.async_address_present(
            self.hass, self._entry.runtime_data.address, connectable=True
        )

    async def async_press(self) -> None:
        try:
            await self._entry.runtime_data.perform(PRIMARY_ACTION)
        except BluegateAuthError as exc:
            # Key revoked or never enrolled: ask the user to enrol a new one.
            self._entry.async_start_reauth(self.hass)
            raise HomeAssistantError("The device rejected Home Assistant's key") from exc
        except BluegateConnectionError as exc:
            raise HomeAssistantError(f"Could not reach the device: {exc}") from exc
