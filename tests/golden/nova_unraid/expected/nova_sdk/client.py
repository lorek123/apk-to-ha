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
ACTION_DOC_UPDATE_CONTAINER = "mutation UpdateContainer($id: PrefixedID!) { docker { updateContainer(id: $id) { id state } } }"
ACTION_DOC_REBOOT_VM = "mutation RebootVm($id: PrefixedID!) { vm { reboot(id: $id) } }"
ACTION_DOC_GET_PLUGIN_OPERATIONS = "query GetPluginOperations { pluginInstallOperations { id url name status createdAt finishedAt output } }"
ACTION_DOC_ARCHIVE_NOTIFICATION = "mutation ArchiveNotification($id: PrefixedID!) { archiveNotification(id: $id) { id } }"
ACTION_DOC_PAUSE_CONTAINER = "mutation PauseContainer($id: PrefixedID!) { docker { pause(id: $id) { id state } } }"
ACTION_DOC_GET_NOTIFICATIONS = "query GetNotifications { notifications { overview { unread { info warning alert total } } warningsAndAlerts { id title subject description importance timestamp } } }"
ACTION_DOC_PAUSE_VM = "mutation PauseVm($id: PrefixedID!) { vm { pause(id: $id) } }"
ACTION_DOC_GET_NETWORK_THROUGHPUT = "query GetNetworkThroughput { metrics { network { interfaces { iface rxBytesPerSec txBytesPerSec } } } }"
ACTION_DOC_STOP_VM = "mutation StopVm($id: PrefixedID!) { vm { stop(id: $id) } }"
ACTION_DOC_DELETE_NOTIFICATION = "mutation DeleteNotification($id: PrefixedID!, $type: NotificationType!) { deleteNotification(id: $id, type: $type) { unread { warning alert } } }"
ACTION_DOC_UNREAD_NOTIFICATION = "mutation UnreadNotification($id: PrefixedID!) { unreadNotification(id: $id) { id } }"
ACTION_DOC_START_CONTAINER = "mutation StartContainer($id: PrefixedID!) { docker { start(id: $id) { id state } } }"
ACTION_DOC_GET_DOCKER_CONTAINERS = "query GetDockerContainers { docker { containers { id names image state status autoStart iconUrl isUpdateAvailable isRebuildReady webUiUrl ports { privatePort publicPort type } mounts networkSettings } } }"
ACTION_DOC_START_VM = "mutation StartVm($id: PrefixedID!) { vm { start(id: $id) } }"
ACTION_DOC_START_PARITY_CHECK = "mutation StartParityCheck($correct: Boolean!) { parityCheck { start(correct: $correct) } }"
ACTION_DOC_PING = "query Ping { __typename }"
ACTION_DOC_GET_INSTALLED_UNRAID_PLUGINS = "query GetInstalledUnraidPlugins { installedUnraidPlugins }"
ACTION_DOC_FORCE_STOP_VM = "mutation ForceStopVm($id: PrefixedID!) { vm { forceStop(id: $id) } }"
ACTION_DOC_GET_PLUGINS = "query GetPlugins { plugins { name version hasApiModule hasCliModule } }"
ACTION_DOC_FETCH_CONTAINER_LOGS = "query FetchContainerLogs($id: PrefixedID!, $tail: Int) { docker { logs(id: $id, tail: $tail) { lines { timestamp message } cursor } } }"
ACTION_DOC_GET_NETWORK_INTERFACES = "query GetNetworkInterfaces { info { networkInterfaces { name description macAddress status protocol ipAddress netmask gateway useDhcp ipv6Address ipv6Netmask ipv6Gateway useDhcp6 } primaryNetwork { name } devices { network { iface model vendor mac virtual speed dhcp } } } }"
ACTION_DOC_RESUME_VM = "mutation ResumeVm($id: PrefixedID!) { vm { resume(id: $id) } }"
ACTION_DOC_STOP_CONTAINER = "mutation StopContainer($id: PrefixedID!) { docker { stop(id: $id) { id state } } }"
ACTION_DOC_UNPAUSE_CONTAINER = "mutation UnpauseContainer($id: PrefixedID!) { docker { unpause(id: $id) { id state } } }"
ACTION_DOC_RESET_VM = "mutation ResetVm($id: PrefixedID!) { vm { reset(id: $id) } }"
ACTION_DOC_GET_VMS = "query GetVms { vms { domains { id name state } } }"
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

    async def update_container(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION UpdateContainer."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "UpdateContainer", ACTION_DOC_UPDATE_CONTAINER, params
        )

    async def reboot_vm(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION RebootVm."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "RebootVm", ACTION_DOC_REBOOT_VM, params
        )

    async def get_plugin_operations(self) -> dict[str, Any]:
        """QUERY GetPluginOperations."""
        params: dict[str, Any] = {}
        return await self._execute(
            "GetPluginOperations", ACTION_DOC_GET_PLUGIN_OPERATIONS, params
        )

    async def archive_notification(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION ArchiveNotification."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "ArchiveNotification", ACTION_DOC_ARCHIVE_NOTIFICATION, params
        )

    async def pause_container(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION PauseContainer."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "PauseContainer", ACTION_DOC_PAUSE_CONTAINER, params
        )

    async def get_notifications(self) -> dict[str, Any]:
        """QUERY GetNotifications."""
        params: dict[str, Any] = {}
        return await self._execute(
            "GetNotifications", ACTION_DOC_GET_NOTIFICATIONS, params
        )

    async def pause_vm(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION PauseVm."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "PauseVm", ACTION_DOC_PAUSE_VM, params
        )

    async def get_network_throughput(self) -> dict[str, Any]:
        """QUERY GetNetworkThroughput."""
        params: dict[str, Any] = {}
        return await self._execute(
            "GetNetworkThroughput", ACTION_DOC_GET_NETWORK_THROUGHPUT, params
        )

    async def stop_vm(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION StopVm."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "StopVm", ACTION_DOC_STOP_VM, params
        )

    async def delete_notification(
        self,
        *,
        id: str,
        type: str,
    ) -> None:
        """MUTATION DeleteNotification."""
        params: dict[str, Any] = {
            "id": id,
            "type": type,
        }
        await self._execute(
            "DeleteNotification", ACTION_DOC_DELETE_NOTIFICATION, params
        )

    async def unread_notification(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION UnreadNotification."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "UnreadNotification", ACTION_DOC_UNREAD_NOTIFICATION, params
        )

    async def start_container(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION StartContainer."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "StartContainer", ACTION_DOC_START_CONTAINER, params
        )

    async def get_docker_containers(self) -> dict[str, Any]:
        """QUERY GetDockerContainers."""
        params: dict[str, Any] = {}
        return await self._execute(
            "GetDockerContainers", ACTION_DOC_GET_DOCKER_CONTAINERS, params
        )

    async def start_vm(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION StartVm."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "StartVm", ACTION_DOC_START_VM, params
        )

    async def start_parity_check(
        self,
        *,
        correct: bool,
    ) -> None:
        """MUTATION StartParityCheck."""
        params: dict[str, Any] = {
            "correct": correct,
        }
        await self._execute(
            "StartParityCheck", ACTION_DOC_START_PARITY_CHECK, params
        )

    async def ping(self) -> dict[str, Any]:
        """QUERY Ping."""
        params: dict[str, Any] = {}
        return await self._execute(
            "Ping", ACTION_DOC_PING, params
        )

    async def get_installed_unraid_plugins(self) -> dict[str, Any]:
        """QUERY GetInstalledUnraidPlugins."""
        params: dict[str, Any] = {}
        return await self._execute(
            "GetInstalledUnraidPlugins", ACTION_DOC_GET_INSTALLED_UNRAID_PLUGINS, params
        )

    async def force_stop_vm(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION ForceStopVm."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "ForceStopVm", ACTION_DOC_FORCE_STOP_VM, params
        )

    async def get_plugins(self) -> dict[str, Any]:
        """QUERY GetPlugins."""
        params: dict[str, Any] = {}
        return await self._execute(
            "GetPlugins", ACTION_DOC_GET_PLUGINS, params
        )

    async def fetch_container_logs(
        self,
        *,
        id: str,
        tail: int | None = None,
    ) -> dict[str, Any]:
        """QUERY FetchContainerLogs."""
        params: dict[str, Any] = {
            "id": id,
        }
        if tail is not None:
            params["tail"] = tail
        return await self._execute(
            "FetchContainerLogs", ACTION_DOC_FETCH_CONTAINER_LOGS, params
        )

    async def get_network_interfaces(self) -> dict[str, Any]:
        """QUERY GetNetworkInterfaces."""
        params: dict[str, Any] = {}
        return await self._execute(
            "GetNetworkInterfaces", ACTION_DOC_GET_NETWORK_INTERFACES, params
        )

    async def resume_vm(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION ResumeVm."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "ResumeVm", ACTION_DOC_RESUME_VM, params
        )

    async def stop_container(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION StopContainer."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "StopContainer", ACTION_DOC_STOP_CONTAINER, params
        )

    async def unpause_container(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION UnpauseContainer."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "UnpauseContainer", ACTION_DOC_UNPAUSE_CONTAINER, params
        )

    async def reset_vm(
        self,
        *,
        id: str,
    ) -> None:
        """MUTATION ResetVm."""
        params: dict[str, Any] = {
            "id": id,
        }
        await self._execute(
            "ResetVm", ACTION_DOC_RESET_VM, params
        )

    async def get_vms(self) -> dict[str, Any]:
        """QUERY GetVms."""
        params: dict[str, Any] = {}
        return await self._execute(
            "GetVms", ACTION_DOC_GET_VMS, params
        )

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
