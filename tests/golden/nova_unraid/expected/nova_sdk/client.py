# SPDX-License-Identifier: MIT
"""GraphQL client for NOVA (/graphql)."""
from __future__ import annotations

import logging
from typing import Any

import aiohttp

from .models import RobotState

_LOGGER = logging.getLogger(__name__)

GRAPHQL_PATH = "/graphql"
API_KEY_HEADER = "x-api-key"
REQUEST_TIMEOUT = 15.0

# Queries fetched together on each refresh; their results share one state object.
STATE_QUERIES: list[tuple[str, str]] = [
    ("GetNotificationList", "query GetNotificationList { notifications { overview { unread { info warning alert total } } unread: list(filter: { type: UNREAD offset: 0 limit: 200 } ) { __typename ...NotificationFields } archived: list(filter: { type: ARCHIVE offset: 0 limit: 200 } ) { __typename ...NotificationFields } } }  fragment NotificationFields on Notification { id title subject description importance link type timestamp formattedTimestamp }"),
    ("GetArray", "query GetArray { array { state capacity { kilobytes { total used free } } parities { id name device size status temp type isSpinning rotational numErrors warning critical } disks { id name device size status temp fsSize fsFree fsUsed type isSpinning rotational numErrors warning critical } caches { id name device size status temp fsSize fsFree fsUsed type isSpinning rotational numErrors warning critical } parityCheckStatus { progress speed errors running paused } } }"),
    ("GetDisplay", "query GetDisplay { display { hot max warning critical } }"),
    ("GetServerInfo", "query GetServerInfo { info { cpu { brand cores threads speedmax } memory { layout { size } } os { hostname kernel uptime } versions { core { unraid kernel } } } }"),
    ("GetMetrics", "query GetMetrics { metrics { cpu { percentTotal } memory { total used buffcache } temperature { sensors { name type current { value unit status } warning critical } } } }"),
]
DOC_STOP_ARRAY = "mutation StopArray { array { setState(input: { desiredState: STOP } ) { state } } }"
DOC_RESUME_PARITY_CHECK = "mutation ResumeParityCheck { parityCheck { resume } }"
DOC_START_ARRAY = "mutation StartArray { array { setState(input: { desiredState: START } ) { state } } }"
DOC_ARCHIVE_ALL_NOTIFICATIONS = "mutation ArchiveAllNotifications { archiveAll { unread { warning alert } } }"
DOC_RECALCULATE_NOTIFICATION_OVERVIEW = "mutation RecalculateNotificationOverview { recalculateOverview { unread { warning alert } } }"
DOC_CANCEL_PARITY_CHECK = "mutation CancelParityCheck { parityCheck { cancel } }"
DOC_DELETE_ARCHIVED_NOTIFICATIONS = "mutation DeleteArchivedNotifications { deleteArchivedNotifications { unread { info warning alert total } } }"
DOC_PAUSE_PARITY_CHECK = "mutation PauseParityCheck { parityCheck { pause } }"
DOC_UPDATE_ALL_CONTAINERS = "mutation UpdateAllContainers { docker { updateAllContainers { id state } } }"
_UNAUTHORIZED = ("unauthorized", "unauthenticated", "forbidden", "invalid api key")


class NovaConnectionError(Exception):
    """The server can't be reached or answered with an error."""


class NovaAuthError(NovaConnectionError):
    """The server rejected the credentials."""


class NovaClient:
    """Runs GraphQL operations against NOVA at *url*."""

    def __init__(
        self,
        url: str,
        session: aiohttp.ClientSession,
        api_key: str,
    ) -> None:
        self._endpoint = url.rstrip("/") + GRAPHQL_PATH
        self._session = session
        self._headers = {API_KEY_HEADER: api_key}

    @property
    def host(self) -> str:
        return self._endpoint

    async def get_state(self) -> RobotState:
        merged: dict[str, Any] = {}
        for name, document in STATE_QUERIES:
            merged.update(await self._execute(name, document))
        return RobotState.from_dict(merged)

    async def disconnect(self) -> None:
        """Nothing to close: the session belongs to Home Assistant."""

    async def press_stop_array(self) -> None:
        await self._execute("StopArray", DOC_STOP_ARRAY)

    async def press_resume_parity_check(self) -> None:
        await self._execute("ResumeParityCheck", DOC_RESUME_PARITY_CHECK)

    async def press_start_array(self) -> None:
        await self._execute("StartArray", DOC_START_ARRAY)

    async def press_archive_all_notifications(self) -> None:
        await self._execute("ArchiveAllNotifications", DOC_ARCHIVE_ALL_NOTIFICATIONS)

    async def press_recalculate_notification_overview(self) -> None:
        await self._execute("RecalculateNotificationOverview", DOC_RECALCULATE_NOTIFICATION_OVERVIEW)

    async def press_cancel_parity_check(self) -> None:
        await self._execute("CancelParityCheck", DOC_CANCEL_PARITY_CHECK)

    async def press_delete_archived_notifications(self) -> None:
        await self._execute("DeleteArchivedNotifications", DOC_DELETE_ARCHIVED_NOTIFICATIONS)

    async def press_pause_parity_check(self) -> None:
        await self._execute("PauseParityCheck", DOC_PAUSE_PARITY_CHECK)

    async def press_update_all_containers(self) -> None:
        await self._execute("UpdateAllContainers", DOC_UPDATE_ALL_CONTAINERS)

    async def _execute(
        self, name: str, document: str, variables: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload = {"query": document, "operationName": name, "variables": variables or {}}
        try:
            async with self._session.post(
                self._endpoint,
                json=payload,
                headers=self._headers,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ) as resp:
                if resp.status in (401, 403):
                    raise NovaAuthError(f"{name}: HTTP {resp.status}")
                resp.raise_for_status()
                body = await resp.json()
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise NovaConnectionError(f"{name} failed: {exc!r}") from exc
        errors = body.get("errors") or []
        if errors:
            message = str(errors[0].get("message", errors[0]))
            if any(word in message.lower() for word in _UNAUTHORIZED):
                raise NovaAuthError(f"{name}: {message}")
            raise NovaConnectionError(f"{name}: {message}")
        data = body.get("data")
        if not isinstance(data, dict):
            raise NovaConnectionError(f"{name}: response has no data")
        return data
