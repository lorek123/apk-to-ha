# SPDX-License-Identifier: MIT
"""Diagnostics for Firepit."""
from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant

from . import FirepitConfigEntry


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: FirepitConfigEntry
) -> dict[str, Any]:
    coordinator = entry.runtime_data
    return {
        "entry": entry.as_dict(),
        "device_info": coordinator.device_info,
        "state": coordinator.data,
        "last_update_success": coordinator.last_update_success,
    }
