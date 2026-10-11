# SPDX-License-Identifier: MIT
"""Base entity for JBL Portable."""
from __future__ import annotations

from typing import Any

from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from jbllink_sdk import JbllinkConnectionError, model

from .const import DOMAIN
from .coordinator import JbllinkCoordinator


class JbllinkEntity(CoordinatorEntity[JbllinkCoordinator]):
    """An entity showing one state field of the device."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: JbllinkCoordinator, key: str, field: str) -> None:
        super().__init__(coordinator)
        self._field = field
        self._attr_translation_key = key
        address = coordinator.client.address
        self._attr_unique_id = f"{address}_{key}"
        info = coordinator.device_info
        model_name, _ = model(info.get("product_id"))
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, address)},
            identifiers={(DOMAIN, address)},
            name=coordinator.config_entry.title,
            model=model_name,
            model_id=info.get("product_id"),
            sw_version=info.get("firmware_version"),
        )

    @property
    def value(self) -> Any:
        return (self.coordinator.data or {}).get(self._field)

    @property
    def available(self) -> bool:
        return super().available and self.value is not None

    async def _apply(self, key: str, value: int) -> None:
        try:
            await self.coordinator.async_apply(key, value)
        except JbllinkConnectionError as err:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="write_failed",
                translation_placeholders={"error": str(err)},
            ) from err
