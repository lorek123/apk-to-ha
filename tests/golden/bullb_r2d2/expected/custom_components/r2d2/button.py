# SPDX-License-Identifier: MIT
"""Button platform for Build Your Own R2-D2."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
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
    client = coordinator.client
    async_add_entities([
        R2D2Button(
            coordinator,
            "reset_mcu",
            "reset_mcu",
            client.press_reset_mcu,
            maintenance=True,
            device_class=ButtonDeviceClass.RESTART,
        ),
        R2D2Button(
            coordinator,
            "d_head_power",
            "d_head_power",
            client.press_d_head_power,
            maintenance=True,
            device_class=None,
        ),
        R2D2Button(
            coordinator,
            "d_leg_power",
            "d_leg_power",
            client.press_d_leg_power,
            maintenance=True,
            device_class=None,
        ),
    ])


class R2D2Button(R2D2Entity, ButtonEntity):
    def __init__(
        self,
        coordinator: R2D2Coordinator,
        key: str,
        translation_key: str,
        press: Callable[[], Awaitable[None]],
        *,
        maintenance: bool,
        device_class: ButtonDeviceClass | None,
    ) -> None:
        super().__init__(coordinator, key)
        self._attr_translation_key = translation_key
        self._attr_device_class = device_class
        self._press = press
        if maintenance:
            # Resets, debug power toggles, updates: not for everyday dashboards.
            self._attr_entity_category = EntityCategory.CONFIG
            self._attr_entity_registry_enabled_default = False

    async def async_press(self) -> None:
        await self._press()
