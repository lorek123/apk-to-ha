# SPDX-License-Identifier: MIT
"""Protocol constants for Smart Radio Telescope."""
from __future__ import annotations

DEFAULT_PORT: int = 8887
CMD_AUTH: str = "grantAccess"
CMD_STATE_PUSH: str = "gin"
CMD_SHUTDOWN: str = "POST /shutdown"
CMD_HOME: str = "POST /home"
CMD_STOP: str = "POST /stop"
CMD_SLEEP: str = "POST /sleep"
CMD_WAKE: str = "POST /wake"
CMD_ADC_RATE: str = "POST /adc_rate"
