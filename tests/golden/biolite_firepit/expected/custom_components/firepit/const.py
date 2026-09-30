# SPDX-License-Identifier: MIT
"""Constants for Firepit integration."""
from datetime import timedelta

DOMAIN = "firepit"
# Each refresh opens a Bluetooth connection, reads every value and closes it.
POLL_INTERVAL = timedelta(seconds=30)
