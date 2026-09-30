# SPDX-License-Identifier: MIT
"""Binary sensor platform for Firepit."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import FirepitConfigEntry
from .coordinator import FirepitCoordinator
from .entity_base import FirepitEntity

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: FirepitConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities([
        FirepitBinarySensor(coordinator, "usb_output_control"),
    ])


class FirepitBinarySensor(FirepitEntity, BinarySensorEntity):
    def __init__(self, coordinator: FirepitCoordinator, key: str) -> None:
        super().__init__(coordinator, key)
        self._attr_translation_key = key

    @property
    def is_on(self) -> bool | None:
        value = self.value
        return None if value is None else bool(value)
