# SPDX-License-Identifier: MIT
"""Shared entity base for Inkcast integration."""
from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import InkcastCoordinator


class InkcastEntity(CoordinatorEntity[InkcastCoordinator]):
    """Base entity: wires device_info and unique_id from the config entry."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: InkcastCoordinator,
        unique_suffix: str,
    ) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.entry_id}_{unique_suffix}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=entry.title,
            manufacturer="Inkcast",
        )
