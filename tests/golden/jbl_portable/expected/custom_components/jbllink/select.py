# SPDX-License-Identifier: MIT
"""Select platform for JBL Portable: settings whose values the app names."""
from __future__ import annotations

from dataclasses import dataclass, field

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import JbllinkConfigEntry
from .coordinator import JbllinkCoordinator
from .entity_base import JbllinkEntity

PARALLEL_UPDATES = 1


@dataclass(frozen=True, kw_only=True)
class JbllinkSelectDescription(SelectEntityDescription):
    field: str
    values: dict[str, int] = field(default_factory=dict)  # option → value sent


SELECTS: tuple[JbllinkSelectDescription, ...] = (
    JbllinkSelectDescription(
        key="eq_mode",
        field="eq_mode",
        options=["indoor", "outdoor", ],
        values={ "indoor": 0, "outdoor": 1, },
        entity_category=EntityCategory.CONFIG,
    ),
    JbllinkSelectDescription(
        key="mfb",
        field="mfb_status",
        options=["play_pause", "voice", ],
        values={ "play_pause": 0, "voice": 1, },
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
        JbllinkSelect(coordinator, d) for d in SELECTS if d.field in coordinator.data
    )


class JbllinkSelect(JbllinkEntity, SelectEntity):
    entity_description: JbllinkSelectDescription

    def __init__(
        self, coordinator: JbllinkCoordinator, description: JbllinkSelectDescription
    ) -> None:
        super().__init__(coordinator, description.key, description.field)
        self.entity_description = description

    @property
    def current_option(self) -> str | None:
        value = self.value
        return next(
            (o for o, v in self.entity_description.values.items() if v == value), None
        )

    async def async_select_option(self, option: str) -> None:
        await self._apply(self.entity_description.key, self.entity_description.values[option])
