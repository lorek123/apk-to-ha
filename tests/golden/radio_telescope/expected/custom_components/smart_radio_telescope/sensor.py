# SPDX-License-Identifier: MIT
"""Sensor platform for Smart Radio Telescope."""
from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import SmartRadioTelescopeCoordinator
from .entity_base import SmartRadioTelescopeEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    entities: list[SensorEntity] = []
    coordinator: SmartRadioTelescopeCoordinator = entry.runtime_data.coordinator
    entities.extend([
        SmartRadioTelescopeSensor(
            coordinator,
            "az",
            "az",
            "az",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        SmartRadioTelescopeSensor(
            coordinator,
            "el",
            "el",
            "el",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        SmartRadioTelescopeSensor(
            coordinator,
            "pol",
            "pol",
            "pol",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        SmartRadioTelescopeSensor(
            coordinator,
            "temp_c",
            "temp_c",
            "temp_c",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        SmartRadioTelescopeSensor(
            coordinator,
            "adc_v",
            "adc_v",
            "adc_v",
            device_class=None,
            unit=None,
            state_class=None,
        ),
    ])
    async_add_entities(entities)


class SmartRadioTelescopeSensor(SmartRadioTelescopeEntity, SensorEntity):
    def __init__(
        self,
        coordinator: SmartRadioTelescopeCoordinator,
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
