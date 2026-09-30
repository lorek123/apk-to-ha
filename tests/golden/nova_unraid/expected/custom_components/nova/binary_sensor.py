# SPDX-License-Identifier: MIT
"""Binary sensor platform for NOVA."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import NovaCoordinator
from .entity_base import NovaEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: NovaCoordinator = entry.runtime_data.coordinator
    async_add_entities([
        NovaBinarySensor(
            coordinator,
            "array.parityCheckStatus.paused",
            "array_paritycheckstatus_paused",
            "array_parity_check_status_paused",
            None,
        ),
        NovaBinarySensor(
            coordinator,
            "array.parityCheckStatus.running",
            "array_paritycheckstatus_running",
            "array_parity_check_status_running",
            None,
        ),
    ])


class NovaBinarySensor(NovaEntity, BinarySensorEntity):
    def __init__(
        self,
        coordinator: NovaCoordinator,
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
