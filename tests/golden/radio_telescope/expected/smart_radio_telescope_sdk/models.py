# SPDX-License-Identifier: MIT
"""State model for Smart Radio Telescope."""
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
    az: int | float | str | None = None
    el: int | float | str | None = None
    pol: int | float | str | None = None
    temp_c: int | float | str | None = None
    adc_v: int | float | str | None = None
    moving: bool | None = None
    homed: bool | None = None
    fault: bool | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "RobotState":
        return cls(
            az=_get(data, "az"),
            el=_get(data, "el"),
            pol=_get(data, "pol"),
            temp_c=_get(data, "temp_c"),
            adc_v=_get(data, "adc_v"),
            moving=_opt_bool(_get(data, "moving")),
            homed=_opt_bool(_get(data, "homed")),
            fault=_opt_bool(_get(data, "fault")),
        )
