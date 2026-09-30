# SPDX-License-Identifier: MIT
"""Switch platform for Firepit."""
from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import FirepitConfigEntry
from .coordinator import FirepitCoordinator
from .entity_base import FirepitEntity

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    entry: FirepitConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities([
        FirepitSwitch(coordinator, "usb_charge_out", coordinator.client.set_usb_charge_out),
    ])


class FirepitSwitch(FirepitEntity, SwitchEntity):
    def __init__(
        self, coordinator: FirepitCoordinator, key: str, set_on: Any
    ) -> None:
        super().__init__(coordinator, key)
        self._attr_translation_key = key
        self._set_on = set_on

    @property
    def is_on(self) -> bool | None:
        value = self.value
        return None if value is None else bool(value)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._send(self._set_on(True), 1)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._send(self._set_on(False), 0)
