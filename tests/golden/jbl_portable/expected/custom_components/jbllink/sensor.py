# SPDX-License-Identifier: MIT
"""Sensor platform for JBL Portable."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import JbllinkConfigEntry
from .coordinator import JbllinkCoordinator
from .entity_base import JbllinkEntity

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)
class JbllinkSensorDescription(SensorEntityDescription):
    field: str


SENSORS: tuple[JbllinkSensorDescription, ...] = (
    JbllinkSensorDescription(
        key="battery",
        field="battery_status",
        device_class=SensorDeviceClass.BATTERY,
        native_unit_of_measurement="%",
        state_class=SensorStateClass.MEASUREMENT,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: JbllinkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    # Models answer different subsets of the protocol: only what this one answered.
    async_add_entities(
        JbllinkSensor(coordinator, d) for d in SENSORS if d.field in coordinator.data
    )


class JbllinkSensor(JbllinkEntity, SensorEntity):
    entity_description: JbllinkSensorDescription

    def __init__(
        self, coordinator: JbllinkCoordinator, description: JbllinkSensorDescription
    ) -> None:
        super().__init__(coordinator, description.key, description.field)
        self.entity_description = description
        self._attr_translation_key = None  # named by its device class

    @property
    def native_value(self) -> int | None:
        value = self.value
        return value if isinstance(value, int) else None
