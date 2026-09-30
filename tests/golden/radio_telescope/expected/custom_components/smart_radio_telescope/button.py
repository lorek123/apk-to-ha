# SPDX-License-Identifier: MIT
"""Button platform for Smart Radio Telescope."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import SmartRadioTelescopeCoordinator
from .entity_base import SmartRadioTelescopeEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: SmartRadioTelescopeCoordinator = entry.runtime_data.coordinator
    client = coordinator.client
    async_add_entities([
        SmartRadioTelescopeButton(
            coordinator,
            "shutdown",
            "shutdown",
            client.press_shutdown,
            maintenance=True,
            device_class=None,
        ),
        SmartRadioTelescopeButton(
            coordinator,
            "home",
            "home",
            client.press_home,
            maintenance=False,
            device_class=None,
        ),
        SmartRadioTelescopeButton(
            coordinator,
            "stop",
            "stop",
            client.press_stop,
            maintenance=False,
            device_class=None,
        ),
        SmartRadioTelescopeButton(
            coordinator,
            "sleep",
            "sleep",
            client.press_sleep,
            maintenance=False,
            device_class=None,
        ),
        SmartRadioTelescopeButton(
            coordinator,
            "wake",
            "wake",
            client.press_wake,
            maintenance=False,
            device_class=None,
        ),
    ])


class SmartRadioTelescopeButton(SmartRadioTelescopeEntity, ButtonEntity):
    def __init__(
        self,
        coordinator: SmartRadioTelescopeCoordinator,
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
