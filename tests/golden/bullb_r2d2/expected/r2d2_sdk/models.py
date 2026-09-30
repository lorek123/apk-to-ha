# SPDX-License-Identifier: MIT
"""State model for Build Your Own R2-D2."""
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
    battery: int | float | str | None = None
    error: int | float | str | None = None
    mode: int | float | str | None = None
    projector: int | float | str | None = None
    arm: bool | None = None
    charging: bool | None = None
    isAPMode: bool | None = None
    lightsaber: bool | None = None
    longLCD: bool | None = None
    shortLCD: bool | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "RobotState":
        return cls(
            battery=_get(data, "battery"),
            error=_get(data, "error"),
            mode=_get(data, "mode"),
            projector=_get(data, "projector"),
            arm=_opt_bool(_get(data, "arm")),
            charging=_opt_bool(_get(data, "charging")),
            isAPMode=_opt_bool(_get(data, "ap_mode")),
            lightsaber=_opt_bool(_get(data, "lightsaber")),
            longLCD=_opt_bool(_get(data, "lcd_l")),
            shortLCD=_opt_bool(_get(data, "lcd_s")),
        )
