# SPDX-License-Identifier: MIT
"""Constants for JBL Portable integration."""
from datetime import timedelta

DOMAIN = "jbllink"
# Each refresh opens a Bluetooth connection, sends the state requests and closes it.
POLL_INTERVAL = timedelta(seconds=60)
