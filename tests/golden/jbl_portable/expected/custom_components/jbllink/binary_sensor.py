# SPDX-License-Identifier: MIT
"""Binary sensor platform for JBL Portable."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import JbllinkConfigEntry
from .coordinator import JbllinkCoordinator
from .entity_base import JbllinkEntity

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class JbllinkBinarySensorDescription(BinarySensorEntityDescription):
    field: str


BINARY_SENSORS: tuple[JbllinkBinarySensorDescription, ...] = (
    JbllinkBinarySensorDescription(
        key="charging",
        field="battery_status_charging",
        device_class=BinarySensorDeviceClass.BATTERY_CHARGING,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: JbllinkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(
        JbllinkBinarySensor(coordinator, d)
        for d in BINARY_SENSORS
        if d.field in coordinator.data
    )


class JbllinkBinarySensor(JbllinkEntity, BinarySensorEntity):
    entity_description: JbllinkBinarySensorDescription

    def __init__(
        self,
        coordinator: JbllinkCoordinator,
        description: JbllinkBinarySensorDescription,
    ) -> None:
        super().__init__(coordinator, description.key, description.field)
        self.entity_description = description
        self._attr_translation_key = None  # named by its device class

    @property
    def is_on(self) -> bool | None:
        value = self.value
        return None if value is None else bool(value)
