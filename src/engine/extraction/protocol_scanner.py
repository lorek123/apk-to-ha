# SPDX-License-Identifier: MIT
"""P2-1..P2-3 — Static protocol extraction for Native Java/Kotlin APKs.

Scans the decompiled source tree for:
  - WebSocket connections (org.java_websocket, okhttp3 WebSocket, aiohttp)
  - Retrofit @GET/@POST/@PUT/@DELETE annotations
  - UDP broadcast patterns
  - BLE GattCharacteristic patterns
  - JSON command constants and their field shapes
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from ..ir.models import (
    AuthScheme,
    AuthType,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    FieldDef,
    FieldKind,
    StateSchema,
    TransportContract,
    TransportType,
)

_LOGGER = logging.getLogger(__name__)

# ── regex patterns ─────────────────────────────────────────────────────────────

# WebSocket URL patterns: new URI("ws://..."), ws_connect("ws://...")
_WS_URI_RE = re.compile(r'"ws://[^"]*:(\d+)"')
_WS_CLASS_RE = re.compile(r'(WebSocketClient|WebSocket|ws_connect|wss://|ws://)', re.I)

# Retrofit annotations
_RETROFIT_METHOD_RE = re.compile(r'@(GET|POST|PUT|DELETE|PATCH|HEAD)\("([^"]+)"\)')
_RETROFIT_HEADERS_RE = re.compile(r'@Headers\(\{?([^)]+)\}?\)')

# JSON put("cmd", "...") patterns — how Android apps build command objects
_JSON_CMD_RE = re.compile(r'jSONObject\.put\("cmd",\s*"([^"]+)"\)')
_JSON_CMD_CONST_RE = re.compile(r'"cmd",\s*(\w+\.)?([A-Z_]+)\b')
_JSON_FIELD_RE = re.compile(r'jSONObject\.put\("([^"]+)",\s*([^)]+)\)')

# String constants that look like command names
_CMD_CONST_RE = re.compile(r'(?:public\s+)?(?:static\s+)?(?:final\s+)?String\s+(\w+)\s*=\s*"([a-z_][a-z0-9_]*)"')

# WebSocket port extraction
_WS_PORT_RE = re.compile(r'(?:WEBSOCKET_PORT|WS_PORT|PORT)\s*=\s*(\d+)')

# UDP port
_UDP_PORT_RE = re.compile(r'(?:SERVER_PORT|UDP_PORT)\s*=\s*(\d+)')

# SerializedName fields
_SERIALIZED_NAME_RE = re.compile(r'@SerializedName\("([^"]+)"\)\s*(?:private\s+)?(\w+)\s+(\w+);')

# BLE characteristic patterns
_BLE_RE = re.compile(r'BluetoothGatt|BluetoothGattCharacteristic|BleakClient', re.I)


class ProtocolScanner:
    def __init__(self, apk_out_dir: Path) -> None:
        self._sources = apk_out_dir / "sources"
        self._app_sources: list[Path] = []
        self._cmd_constants: dict[str, str] = {}  # CONST_NAME → "cmd_value"

    def scan(self, app_package: str) -> tuple[
        TransportContract,
        DiscoveryMechanism,
        AuthScheme,
        StateSchema,
        list[Endpoint],
        list[Endpoint],
    ]:
        """Return (transport, discovery, auth, state, commands, events)."""
        pkg_path = self._sources / app_package.replace(".", "/")
        if pkg_path.exists():
            self._app_sources = list(pkg_path.rglob("*.java"))
        else:
            # Fallback: all java files minus obvious library dirs
            self._app_sources = [
                f for f in self._sources.rglob("*.java")
                if not any(lib in str(f) for lib in (
                    "androidx/", "android/support/", "com/google/", "kotlin/",
                    "okhttp3/", "retrofit2/", "okio/", "com/squareup/",
                ))
            ]

        _LOGGER.info("Scanning %d source files for app package %s", len(self._app_sources), app_package)

        self._collect_cmd_constants()
        transport = self._detect_transport()
        discovery = self._detect_discovery()
        auth = self._detect_auth()
        state = self._detect_state_schema()
        commands, events = self._extract_endpoints()

        return transport, discovery, auth, state, commands, events

    def _read(self, path: Path) -> str:
        try:
            return path.read_text(errors="replace")
        except OSError:
            return ""

    def _collect_cmd_constants(self) -> None:
        """Pre-pass: collect all String FOO = "bar" command constants."""
        for f in self._app_sources:
            src = self._read(f)
            for match in _CMD_CONST_RE.finditer(src):
                const_name, cmd_value = match.group(1), match.group(2)
                self._cmd_constants[const_name] = cmd_value

    def _detect_transport(self) -> TransportContract:
        port: int | None = None
        has_ws = False
        has_retrofit = False

        for f in self._app_sources:
            src = self._read(f)
            if _WS_CLASS_RE.search(src):
                has_ws = True
                m = _WS_PORT_RE.search(src)
                if m:
                    port = int(m.group(1))
                m2 = _WS_URI_RE.search(src)
                if m2 and not port:
                    port = int(m2.group(1))
            if _RETROFIT_METHOD_RE.search(src):
                has_retrofit = True

        if has_ws:
            _LOGGER.info("Transport: WebSocket port=%s", port)
            return TransportContract(
                type=TransportType.WEBSOCKET,
                port=port,
                host_source="discovered",
                url_template=f"ws://{{host}}:{port}" if port else "ws://{host}",
            )
        if has_retrofit:
            _LOGGER.info("Transport: HTTP REST (Retrofit)")
            return TransportContract(type=TransportType.HTTP_REST, port=80, host_source="manual")

        _LOGGER.warning("Transport: unknown, defaulting to HTTP_REST")
        return TransportContract(type=TransportType.HTTP_REST, host_source="manual")

    def _detect_discovery(self) -> DiscoveryMechanism:
        for f in self._app_sources:
            src = self._read(f)
            if "UDPServer" in src or "DatagramSocket" in src or "DatagramPacket" in src:
                port: int | None = None
                m = _UDP_PORT_RE.search(src)
                if m:
                    port = int(m.group(1))
                # Try to find the broadcast cmd value
                broadcast_cmd: str | None = None
                m2 = re.search(r'"cmd".*?"([^"]+)"', src)
                if m2:
                    broadcast_cmd = m2.group(1)
                _LOGGER.info("Discovery: UDP broadcast port=%s", port)
                return DiscoveryMechanism(
                    type=DiscoveryType.UDP_BROADCAST,
                    port=port,
                    broadcast_cmd=broadcast_cmd,
                )
            if "NsdManager" in src:
                _LOGGER.info("Discovery: Zeroconf/NSD")
                return DiscoveryMechanism(type=DiscoveryType.ZEROCONF)

        return DiscoveryMechanism(type=DiscoveryType.NONE)

    def _detect_auth(self) -> AuthScheme:
        for f in self._app_sources:
            src = self._read(f)
            # Look for grantAccess pattern (WebSocket handshake)
            if '"grantAccess"' in src or "grantAccess" in self._cmd_constants.values():
                fields = [
                    FieldDef(name="uuid", serialized_name="uuid", kind=FieldKind.STRING),
                    FieldDef(name="device_name", serialized_name="device_name", kind=FieldKind.STRING),
                ]
                return AuthScheme(
                    type=AuthType.HANDSHAKE,
                    handshake_cmd="grantAccess",
                    fields=fields,
                    description="Send grantAccess on WebSocket open; robot responds with state + resultCode",
                )
            # API key header
            if "@Headers" in src and ("Authorization" in src or "X-API-Key" in src):
                return AuthScheme(type=AuthType.API_KEY, description="Static API key in headers")

        return AuthScheme(type=AuthType.NONE)

    def _detect_state_schema(self) -> StateSchema:
        """Find the robot state push model (gin command or polling response)."""
        fields: list[FieldDef] = []
        push_cmd: str | None = None

        for f in self._app_sources:
            src = self._read(f)
            if '"gin"' in src:
                push_cmd = "gin"
            # Extract @SerializedName fields from Robot/State model classes
            if "Robot" in f.name or "State" in f.name or "Status" in f.name:
                for m in _SERIALIZED_NAME_RE.finditer(src):
                    json_name, java_type, field_name = m.group(1), m.group(2), m.group(3)
                    kind = _java_type_to_kind(java_type)
                    fields.append(FieldDef(name=field_name, serialized_name=json_name, kind=kind))

        if fields:
            _LOGGER.info("State schema: %d fields, push_cmd=%s", len(fields), push_cmd)
        return StateSchema(push_cmd=push_cmd, fields=fields)

    def _extract_endpoints(self) -> tuple[list[Endpoint], list[Endpoint]]:
        """Extract all commands (app→device) and events (device→app)."""
        commands: list[Endpoint] = []
        events: list[Endpoint] = []

        # Collect all JSON command call sites grouped by source file
        for f in self._app_sources:
            src = self._read(f)
            if 'jSONObject.put("cmd"' not in src and '"cmd"' not in src:
                continue

            class_name = f.stem
            seen_cmds: set[str] = set()

            for m in _JSON_CMD_RE.finditer(src):
                cmd = m.group(1)
                if cmd in seen_cmds:
                    continue
                seen_cmds.add(cmd)

                fields = _extract_fields_for_cmd(src, cmd)
                awaits = _cmd_awaits_response(src, cmd)
                direction = _infer_direction(src, cmd)

                endpoint = Endpoint(
                    cmd=cmd,
                    transport=TransportType.WEBSOCKET,
                    direction=direction,
                    awaits_response=awaits,
                    request_fields=fields if direction == Direction.TO_DEVICE else [],
                    response_fields=fields if direction == Direction.FROM_DEVICE else [],
                    source_class=class_name,
                )
                if direction == Direction.FROM_DEVICE:
                    events.append(endpoint)
                else:
                    commands.append(endpoint)

        # Also scan for Retrofit endpoints
        for f in self._app_sources:
            src = self._read(f)
            for m in _RETROFIT_METHOD_RE.finditer(src):
                verb, path = m.group(1), m.group(2)
                commands.append(Endpoint(
                    cmd=f"{verb} {path}",
                    transport=TransportType.HTTP_REST,
                    direction=Direction.TO_DEVICE,
                    awaits_response=True,
                    source_class=f.stem,
                ))

        _LOGGER.info("Extracted %d commands, %d events", len(commands), len(events))
        return commands, events


# ── helpers ────────────────────────────────────────────────────────────────────

def _java_type_to_kind(java_type: str) -> FieldKind:
    t = java_type.lower()
    if t in ("string",):
        return FieldKind.STRING
    if t in ("int", "integer", "long", "short", "byte"):
        return FieldKind.INTEGER
    if t in ("float", "double"):
        return FieldKind.NUMBER
    if t in ("boolean", "bool"):
        return FieldKind.BOOLEAN
    if t.startswith("list") or t.endswith("[]") or t.startswith("arraylist"):
        return FieldKind.ARRAY
    return FieldKind.OBJECT


def _extract_fields_for_cmd(src: str, cmd: str) -> list[FieldDef]:
    """Find the jSONObject.put() calls in the same method block as the cmd."""
    fields: list[FieldDef] = []
    # Locate cmd assignment, then scan next ~20 lines for other puts
    idx = src.find(f'"cmd", "{cmd}"')
    if idx == -1:
        return fields
    block = src[idx: idx + 800]
    for m in _JSON_FIELD_RE.finditer(block):
        fname = m.group(1)
        if fname == "cmd" or fname == "seq":
            continue
        rhs = m.group(2).strip()
        kind = _infer_field_kind(rhs)
        fields.append(FieldDef(name=fname, serialized_name=fname, kind=kind))
    return fields


def _infer_field_kind(rhs: str) -> FieldKind:
    if rhs in ("true", "false") or rhs.startswith("enable"):
        return FieldKind.BOOLEAN
    if rhs.isdigit() or re.match(r'^-?\d+$', rhs):
        return FieldKind.INTEGER
    if rhs.startswith('"'):
        return FieldKind.STRING
    return FieldKind.STRING


def _cmd_awaits_response(src: str, cmd: str) -> bool:
    """Heuristic: does this command appear in a response command list?"""
    # Look for ROBOT_RESPONSE_COMMAND_LIST membership patterns
    return "ROBOT_RESPONSE_COMMAND_LIST" in src and f'"{cmd}"' in src


def _infer_direction(src: str, cmd: str) -> Direction:
    """Heuristic: commands in receiveXxx methods or interpretCommand are FROM device."""
    idx = src.find(f'"cmd", "{cmd}"')
    if idx == -1:
        return Direction.TO_DEVICE
    context = src[max(0, idx - 300): idx]
    if any(kw in context for kw in ("receive", "onMessage", "interpretCommand", "broadcast")):
        return Direction.FROM_DEVICE
    return Direction.TO_DEVICE
