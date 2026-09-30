# SPDX-License-Identifier: MIT
"""Protocol constants for Build Your Own R2-D2."""
from __future__ import annotations

DEFAULT_PORT: int = 8887
UDP_PORT: int = 8090
CMD_DISCOVERY: str = "updBroadcast"
CMD_AUTH: str = "grantAccess"
CMD_STATE_PUSH: str = "gin"
CMD_POWER: str = "power"
CMD_MUTE: str = "mute"
CMD_FACE_DETECTION: str = "face_detection"
CMD_VOICE_RECOGNITION: str = "voice_recognition"
CMD_RESET_MCU: str = "reset_mcu"
CMD_D_HEAD_POWER: str = "d-head-power"
CMD_D_LEG_POWER: str = "d-leg-power"
CMD_MODE: str = "mode"

# Mode enum values for CMD_MODE
MODE_ACTIONS: dict[int, str] = {
    0: "play",
    2: "turn_around",
    3: "turn_left",
    4: "turn_right",
    5: "go_forward",
    6: "lightsaber",
    9: "patrol",
    10: "dance",
    12: "walk_circle",
    15: "shake_head",
    16: "arm",
    17: "short_lcd",
    18: "long_lcd",
    19: "projector1",
    20: "projector2",
}
ACTION_TO_MODE: dict[str, int] = {v: k for k, v in MODE_ACTIONS.items()}
