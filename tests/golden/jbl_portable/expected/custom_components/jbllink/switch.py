# SPDX-License-Identifier: MIT
"""Switch platform for JBL Portable: settings the app shows as on/off toggles."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import JbllinkConfigEntry
from .coordinator import JbllinkCoordinator
from .entity_base import JbllinkEntity

PARALLEL_UPDATES = 1


@dataclass(frozen=True, kw_only=True)
class JbllinkSwitchDescription(SwitchEntityDescription):
    field: str
    on: int
    off: int


SWITCHES: tuple[JbllinkSwitchDescription, ...] = (
    JbllinkSwitchDescription(
        key="feedback_tone",
        field="feedback_tone_status",
        on=1,
        off=0,
        entity_category=EntityCategory.CONFIG,
    ),
    JbllinkSwitchDescription(
        key="hfp",
        field="hfp_status",
        on=1,
        off=0,
        entity_category=EntityCategory.CONFIG,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: JbllinkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(
        JbllinkSwitch(coordinator, d) for d in SWITCHES if d.field in coordinator.data
    )


class JbllinkSwitch(JbllinkEntity, SwitchEntity):
    entity_description: JbllinkSwitchDescription

    def __init__(
        self, coordinator: JbllinkCoordinator, description: JbllinkSwitchDescription
    ) -> None:
        super().__init__(coordinator, description.key, description.field)
        self.entity_description = description

    @property
    def is_on(self) -> bool | None:
        value = self.value
        return None if value is None else value == self.entity_description.on

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._apply(self.entity_description.key, self.entity_description.on)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._apply(self.entity_description.key, self.entity_description.off)
