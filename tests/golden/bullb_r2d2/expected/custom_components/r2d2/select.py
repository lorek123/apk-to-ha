# SPDX-License-Identifier: MIT
"""Select platform for Build Your Own R2-D2."""
from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from r2d2_sdk import MODE_ACTIONS

from .coordinator import R2D2Coordinator
from .entity_base import R2D2Entity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: R2D2Coordinator = entry.runtime_data.coordinator
    async_add_entities([
        R2D2ModeSelect(
            coordinator,
            "mode",
            "mode",
            "mode",
        ),
    ])


class R2D2ModeSelect(R2D2Entity, SelectEntity):
    """Mode select; reflects the pushed mode when the device reports it."""

    def __init__(
        self,
        coordinator: R2D2Coordinator,
        key: str,
        translation_key: str,
        state_attr: str | None,
    ) -> None:
        super().__init__(coordinator, key)
        self._attr_translation_key = translation_key
        self._attr_options = list(MODE_ACTIONS.values())
        self._state_attr = state_attr
        self._optimistic: str | None = None

    @property
    def current_option(self) -> str | None:
        if self._state_attr is None:
            return self._optimistic
        value = getattr(self.coordinator.data, self._state_attr, None)
        try:
            return MODE_ACTIONS.get(int(value)) if value is not None else None
        except (TypeError, ValueError):
            return None

    async def async_select_option(self, option: str) -> None:
        await self.coordinator.client.set_mode(option)
        if self._state_attr is None:
            self._optimistic = option
            self.async_write_ha_state()
