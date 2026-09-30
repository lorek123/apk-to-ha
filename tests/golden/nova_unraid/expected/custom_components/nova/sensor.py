# SPDX-License-Identifier: MIT
"""Sensor platform for NOVA."""
from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
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
    entities: list[SensorEntity] = []
    coordinator: NovaCoordinator = entry.runtime_data.coordinator
    entities.extend([
        NovaSensor(
            coordinator,
            "array.capacity.kilobytes.free",
            "array_capacity_kilobytes_free",
            "array_capacity_kilobytes_free",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "array.capacity.kilobytes.total",
            "array_capacity_kilobytes_total",
            "array_capacity_kilobytes_total",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "array.capacity.kilobytes.used",
            "array_capacity_kilobytes_used",
            "array_capacity_kilobytes_used",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "array.parityCheckStatus.errors",
            "array_paritycheckstatus_errors",
            "array_parity_check_status_errors",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "array.parityCheckStatus.progress",
            "array_paritycheckstatus_progress",
            "array_parity_check_status_progress",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "array.parityCheckStatus.speed",
            "array_paritycheckstatus_speed",
            "array_parity_check_status_speed",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "array.state",
            "array_state",
            "array_state",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.cpu.brand",
            "info_cpu_brand",
            "info_cpu_brand",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.cpu.cores",
            "info_cpu_cores",
            "info_cpu_cores",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.cpu.speedmax",
            "info_cpu_speedmax",
            "info_cpu_speedmax",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.cpu.threads",
            "info_cpu_threads",
            "info_cpu_threads",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.os.hostname",
            "info_os_hostname",
            "info_os_hostname",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.os.kernel",
            "info_os_kernel",
            "info_os_kernel",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.os.uptime",
            "info_os_uptime",
            "info_os_uptime",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.versions.core.kernel",
            "info_versions_core_kernel",
            "info_versions_core_kernel",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "info.versions.core.unraid",
            "info_versions_core_unraid",
            "info_versions_core_unraid",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "display.critical",
            "display_critical",
            "display_critical",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "display.hot",
            "display_hot",
            "display_hot",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "display.max",
            "display_max",
            "display_max",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "display.warning",
            "display_warning",
            "display_warning",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "metrics.cpu.percentTotal",
            "metrics_cpu_percenttotal",
            "metrics_cpu_percent_total",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "metrics.memory.buffcache",
            "metrics_memory_buffcache",
            "metrics_memory_buffcache",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "metrics.memory.total",
            "metrics_memory_total",
            "metrics_memory_total",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "metrics.memory.used",
            "metrics_memory_used",
            "metrics_memory_used",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "notifications.overview.unread.alert",
            "notifications_overview_unread_alert",
            "notifications_overview_unread_alert",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "notifications.overview.unread.info",
            "notifications_overview_unread_info",
            "notifications_overview_unread_info",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "notifications.overview.unread.total",
            "notifications_overview_unread_total",
            "notifications_overview_unread_total",
            device_class=None,
            unit=None,
            state_class=None,
        ),
        NovaSensor(
            coordinator,
            "notifications.overview.unread.warning",
            "notifications_overview_unread_warning",
            "notifications_overview_unread_warning",
            device_class=None,
            unit=None,
            state_class=None,
        ),
    ])
    async_add_entities(entities)


class NovaSensor(NovaEntity, SensorEntity):
    def __init__(
        self,
        coordinator: NovaCoordinator,
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
