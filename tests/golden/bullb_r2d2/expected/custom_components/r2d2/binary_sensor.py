# SPDX-License-Identifier: MIT
"""Binary sensor platform for Build Your Own R2-D2."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
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
    coordinator: R2D2Coordinator = entry.runtime_data.coordinator
    async_add_entities([
        R2D2BinarySensor(
            coordinator,
            "arm",
            "arm",
            "arm",
            None,
        ),
        R2D2BinarySensor(
            coordinator,
            "charging",
            "charging",
            "charging",
            BinarySensorDeviceClass.BATTERY_CHARGING,
        ),
        R2D2BinarySensor(
            coordinator,
            "ap_mode",
            "ap_mode",
            "isAPMode",
            None,
        ),
        R2D2BinarySensor(
            coordinator,
            "lightsaber",
            "lightsaber",
            "lightsaber",
            None,
        ),
        R2D2BinarySensor(
            coordinator,
            "lcd_l",
            "lcd_l",
            "longLCD",
            None,
        ),
        R2D2BinarySensor(
            coordinator,
            "lcd_s",
            "lcd_s",
            "shortLCD",
            None,
        ),
    ])


class R2D2BinarySensor(R2D2Entity, BinarySensorEntity):
    def __init__(
        self,
        coordinator: R2D2Coordinator,
        key: str,
        translation_key: str,
        attr: str,
        device_class: BinarySensorDeviceClass | None,
    ) -> None:
        super().__init__(coordinator, key)
        self._attr_translation_key = translation_key
        self._attr_device_class = device_class
        self._attr = attr

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        return getattr(self.coordinator.data, self._attr, None)
