# SPDX-License-Identifier: MIT
"""State model for NOVA."""
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
    array_capacity_kilobytes_free: int | float | str | None = None
    array_capacity_kilobytes_total: int | float | str | None = None
    array_capacity_kilobytes_used: int | float | str | None = None
    array_parity_check_status_errors: int | float | str | None = None
    array_parity_check_status_progress: int | float | str | None = None
    array_parity_check_status_speed: int | float | str | None = None
    array_state: int | float | str | None = None
    info_cpu_brand: int | float | str | None = None
    info_cpu_cores: int | float | str | None = None
    info_cpu_speedmax: int | float | str | None = None
    info_cpu_threads: int | float | str | None = None
    info_os_hostname: int | float | str | None = None
    info_os_kernel: int | float | str | None = None
    info_os_uptime: int | float | str | None = None
    info_versions_core_kernel: int | float | str | None = None
    info_versions_core_unraid: int | float | str | None = None
    display_critical: int | float | str | None = None
    display_hot: int | float | str | None = None
    display_max: int | float | str | None = None
    display_warning: int | float | str | None = None
    metrics_cpu_percent_total: int | float | str | None = None
    metrics_memory_buffcache: int | float | str | None = None
    metrics_memory_total: int | float | str | None = None
    metrics_memory_used: int | float | str | None = None
    notifications_overview_unread_alert: int | float | str | None = None
    notifications_overview_unread_info: int | float | str | None = None
    notifications_overview_unread_total: int | float | str | None = None
    notifications_overview_unread_warning: int | float | str | None = None
    array_parity_check_status_paused: bool | None = None
    array_parity_check_status_running: bool | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "RobotState":
        return cls(
            array_capacity_kilobytes_free=_get(data, "array.capacity.kilobytes.free"),
            array_capacity_kilobytes_total=_get(data, "array.capacity.kilobytes.total"),
            array_capacity_kilobytes_used=_get(data, "array.capacity.kilobytes.used"),
            array_parity_check_status_errors=_get(data, "array.parityCheckStatus.errors"),
            array_parity_check_status_progress=_get(data, "array.parityCheckStatus.progress"),
            array_parity_check_status_speed=_get(data, "array.parityCheckStatus.speed"),
            array_state=_get(data, "array.state"),
            info_cpu_brand=_get(data, "info.cpu.brand"),
            info_cpu_cores=_get(data, "info.cpu.cores"),
            info_cpu_speedmax=_get(data, "info.cpu.speedmax"),
            info_cpu_threads=_get(data, "info.cpu.threads"),
            info_os_hostname=_get(data, "info.os.hostname"),
            info_os_kernel=_get(data, "info.os.kernel"),
            info_os_uptime=_get(data, "info.os.uptime"),
            info_versions_core_kernel=_get(data, "info.versions.core.kernel"),
            info_versions_core_unraid=_get(data, "info.versions.core.unraid"),
            display_critical=_get(data, "display.critical"),
            display_hot=_get(data, "display.hot"),
            display_max=_get(data, "display.max"),
            display_warning=_get(data, "display.warning"),
            metrics_cpu_percent_total=_get(data, "metrics.cpu.percentTotal"),
            metrics_memory_buffcache=_get(data, "metrics.memory.buffcache"),
            metrics_memory_total=_get(data, "metrics.memory.total"),
            metrics_memory_used=_get(data, "metrics.memory.used"),
            notifications_overview_unread_alert=_get(data, "notifications.overview.unread.alert"),
            notifications_overview_unread_info=_get(data, "notifications.overview.unread.info"),
            notifications_overview_unread_total=_get(data, "notifications.overview.unread.total"),
            notifications_overview_unread_warning=_get(data, "notifications.overview.unread.warning"),
            array_parity_check_status_paused=_opt_bool(_get(data, "array.parityCheckStatus.paused")),
            array_parity_check_status_running=_opt_bool(_get(data, "array.parityCheckStatus.running")),
        )
