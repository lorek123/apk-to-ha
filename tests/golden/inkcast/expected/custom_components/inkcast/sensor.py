# SPDX-License-Identifier: MIT
"""Sensor platform for Inkcast."""
from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import InkcastCoordinator
from .entity_base import InkcastEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    entities: list[SensorEntity] = []
    coordinator: InkcastCoordinator = entry.runtime_data.coordinator
    entities.extend([
        InkcastSensor(
            coordinator,
            "freeHeap",
            "freeheap",
            "freeHeap",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        InkcastSensor(
            coordinator,
            "mode",
            "mode",
            "mode",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        InkcastSensor(
            coordinator,
            "rssi",
            "rssi",
            "rssi",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        InkcastSensor(
            coordinator,
            "uptime",
            "uptime",
            "uptime",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        InkcastSensor(
            coordinator,
            "version",
            "version",
            "version",
            device_class=None,
            unit=None,
            state_class=None,
        ),
    ])
    async_add_entities(entities)


class InkcastSensor(InkcastEntity, SensorEntity):
    def __init__(
        self,
        coordinator: InkcastCoordinator,
        key: str,
        translation_key: str,
        attr: str,
        *,
        device_class: SensorDeviceClass | None,
        unit: str | None,
        state_class: SensorStateClass | None,
    ) -> None:
        super().__init__(coordinator, key)
        self._attr_translation_key = translation_key
        self._attr_device_class = device_class
        self._attr_native_unit_of_measurement = unit
        self._attr_state_class = state_class
        self._attr = attr

    @property
    def native_value(self):
        if self.coordinator.data is None:
            return None
        return getattr(self.coordinator.data, self._attr, None)
