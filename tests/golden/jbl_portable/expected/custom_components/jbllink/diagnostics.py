# SPDX-License-Identifier: MIT
"""Diagnostics for JBL Portable."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import JbllinkConfigEntry

TO_REDACT = {"mac_address"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: JbllinkConfigEntry
) -> dict[str, Any]:
    coordinator = entry.runtime_data
    return {
        "entry": entry.as_dict(),
        "device_info": async_redact_data(coordinator.device_info, TO_REDACT),
        "state": coordinator.data,
        "last_update_success": coordinator.last_update_success,
    }
