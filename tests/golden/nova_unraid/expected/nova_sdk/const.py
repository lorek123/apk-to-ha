# SPDX-License-Identifier: MIT
"""Protocol constants for NOVA."""
from __future__ import annotations

DEFAULT_PORT: int = 8887
CMD_AUTH: str = "grantAccess"
CMD_STATE_PUSH: str = "gin"
CMD_STOP_ARRAY: str = "MUTATION StopArray"
CMD_RESUME_PARITY_CHECK: str = "MUTATION ResumeParityCheck"
CMD_START_ARRAY: str = "MUTATION StartArray"
CMD_ARCHIVE_ALL_NOTIFICATIONS: str = "MUTATION ArchiveAllNotifications"
CMD_RECALCULATE_NOTIFICATION_OVERVIEW: str = "MUTATION RecalculateNotificationOverview"
CMD_CANCEL_PARITY_CHECK: str = "MUTATION CancelParityCheck"
CMD_DELETE_ARCHIVED_NOTIFICATIONS: str = "MUTATION DeleteArchivedNotifications"
CMD_PAUSE_PARITY_CHECK: str = "MUTATION PauseParityCheck"
CMD_UPDATE_ALL_CONTAINERS: str = "MUTATION UpdateAllContainers"
