# SPDX-License-Identifier: MIT
"""Button platform for NOVA."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
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
    client = coordinator.client
    async_add_entities([
        NovaButton(
            coordinator,
            "stop_array",
            "stop_array",
            client.press_stop_array,
            maintenance=True,
            device_class=None,
        ),
        NovaButton(
            coordinator,
            "resume_parity_check",
            "resume_parity_check",
            client.press_resume_parity_check,
            maintenance=False,
            device_class=None,
        ),
        NovaButton(
            coordinator,
            "start_array",
            "start_array",
            client.press_start_array,
            maintenance=False,
            device_class=None,
        ),
        NovaButton(
            coordinator,
            "archive_all_notifications",
            "archive_all_notifications",
            client.press_archive_all_notifications,
            maintenance=False,
            device_class=None,
        ),
        NovaButton(
            coordinator,
            "recalculate_notification_overview",
            "recalculate_notification_overview",
            client.press_recalculate_notification_overview,
            maintenance=False,
            device_class=None,
        ),
        NovaButton(
            coordinator,
            "cancel_parity_check",
            "cancel_parity_check",
            client.press_cancel_parity_check,
            maintenance=False,
            device_class=None,
        ),
        NovaButton(
            coordinator,
            "delete_archived_notifications",
            "delete_archived_notifications",
            client.press_delete_archived_notifications,
            maintenance=True,
            device_class=None,
        ),
        NovaButton(
            coordinator,
            "pause_parity_check",
            "pause_parity_check",
            client.press_pause_parity_check,
            maintenance=False,
            device_class=None,
        ),
        NovaButton(
            coordinator,
            "update_all_containers",
            "update_all_containers",
            client.press_update_all_containers,
            maintenance=True,
            device_class=None,
        ),
    ])


class NovaButton(NovaEntity, ButtonEntity):
    def __init__(
        self,
        coordinator: NovaCoordinator,
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
