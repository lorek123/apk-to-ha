# SPDX-License-Identifier: MIT
"""Switch platform for Build Your Own R2-D2."""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import R2D2Coordinator
from .entity_base import R2D2Entity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    entities: list[SwitchEntity] = []
    coordinator: R2D2Coordinator = entry.runtime_data.coordinator
    entities.extend([
        R2D2Switch(
            coordinator,
            "power",
            "power",
            coordinator.client.set_power,
            None,
        ),
        R2D2Switch(
            coordinator,
            "mute",
            "mute",
            coordinator.client.set_mute,
            None,
        ),
        R2D2Switch(
            coordinator,
            "face_detection",
            "face_detection",
            coordinator.client.set_face_detection,
            None,
        ),
        R2D2Switch(
            coordinator,
            "voice_recognition",
            "voice_recognition",
            coordinator.client.set_voice_recognition,
            None,
        ),
    ])
    async_add_entities(entities)


class R2D2Switch(R2D2Entity, SwitchEntity):
    """Reads its state from the device push when the protocol reports it.

    Without a matching state field the switch is optimistic and says so via
    assumed_state, so HA shows both on/off controls instead of a false toggle.
    """

    def __init__(
        self,
        coordinator: R2D2Coordinator,
        key: str,
        translation_key: str,
        set_state: Callable[[bool], Awaitable[None]],
        state_attr: str | None,
    ) -> None:
        super().__init__(coordinator, key)
        self._attr_translation_key = translation_key
        self._set_state = set_state
        self._state_attr = state_attr
        self._attr_assumed_state = state_attr is None
        self._optimistic: bool | None = None

    @property
    def is_on(self) -> bool | None:
        if self._state_attr is None:
            return self._optimistic
        value = getattr(self.coordinator.data, self._state_attr, None)
        return None if value is None else bool(value)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._async_set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._async_set(False)

    async def _async_set(self, enable: bool) -> None:
        await self._set_state(enable)
        if self._state_attr is None:
            self._optimistic = enable
            self.async_write_ha_state()
