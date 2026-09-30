# SPDX-License-Identifier: MIT
"""Base entity for Firepit."""
from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

from firepit_sdk import FirepitConnectionError
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FirepitCoordinator


class FirepitEntity(CoordinatorEntity[FirepitCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: FirepitCoordinator, key: str) -> None:
        super().__init__(coordinator)
        self._key = key
        address = coordinator.client.address
        self._attr_unique_id = f"{address}_{key}"
        info = coordinator.device_info
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, address)},
            identifiers={(DOMAIN, address)},
            name=coordinator.config_entry.title,
            manufacturer=info.get("manufacturer"),
            model=info.get("model"),
            sw_version=info.get("sw_version"),
            hw_version=info.get("hw_version"),
        )

    @property
    def value(self) -> Any:
        return (self.coordinator.data or {}).get(self._key)

    @property
    def available(self) -> bool:
        return super().available and self.value is not None

    async def _send(self, write: Awaitable[None], value: Any) -> None:
        """Run a write; on success show *value* right away."""
        try:
            await write
        except FirepitConnectionError as err:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="write_failed",
                translation_placeholders={"error": str(err)},
            ) from err
        self.coordinator.set_value(self._key, value)
