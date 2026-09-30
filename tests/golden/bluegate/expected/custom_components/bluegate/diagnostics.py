# SPDX-License-Identifier: MIT
"""Diagnostics for BlueGate: the private key is always redacted."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import BluegateConfigEntry
from .const import CONF_PRIVATE_KEY

TO_REDACT = {CONF_PRIVATE_KEY}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: BluegateConfigEntry
) -> dict[str, Any]:
    return {"entry": async_redact_data(entry.as_dict(), TO_REDACT)}
