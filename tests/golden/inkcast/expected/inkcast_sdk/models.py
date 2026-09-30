# SPDX-License-Identifier: MIT
"""State model for Inkcast."""
from __future__ import annotations

from dataclasses import dataclass


def _get(data: dict, key: str) -> object:
    """Value at *key*; dotted keys walk nested objects (GraphQL results)."""
    value: object = data
    for part in key.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _opt_bool(value: object) -> bool | None:
    """Missing stays unknown (None) instead of reading as off."""
    return None if value is None else bool(value)


@dataclass
class RobotState:
    """Parsed state push (gin event)."""
    freeHeap: int | float | str | None = None
    mode: int | float | str | None = None
    rssi: int | float | str | None = None
    uptime: int | float | str | None = None
    version: int | float | str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "RobotState":
        return cls(
            freeHeap=_get(data, "freeHeap"),
            mode=_get(data, "mode"),
            rssi=_get(data, "rssi"),
            uptime=_get(data, "uptime"),
            version=_get(data, "version"),
        )
