# SPDX-License-Identifier: MIT
"""Sensor platform for Build Your Own R2-D2."""
from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import R2D2Coordinator
from .entity_base import R2D2Entity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    entities: list[SensorEntity] = []
    coordinator: R2D2Coordinator = entry.runtime_data.coordinator
    entities.extend([
        R2D2Sensor(
            coordinator,
            "battery",
            "battery",
            "battery",
            device_class=SensorDeviceClass.BATTERY,
            unit="%",
            state_class=SensorStateClass.MEASUREMENT,
        ),
        R2D2Sensor(
            coordinator,
            "error",
            "error",
            "error",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        R2D2Sensor(
            coordinator,
            "projector",
            "projector",
            "projector",
            device_class=None,
            unit=None,
            state_class=None,
        ),
    ])
    async_add_entities(entities)


class R2D2Sensor(R2D2Entity, SensorEntity):
    def __init__(
        self,
        coordinator: R2D2Coordinator,
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
