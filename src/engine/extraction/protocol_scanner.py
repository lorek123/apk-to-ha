# SPDX-License-Identifier: MIT
"""P2-1..P2-3 — Static protocol extraction for Native Java/Kotlin APKs.

Scans the decompiled source tree for:
  - WebSocket connections and port
  - UDP broadcast patterns
  - JSON commands (both literal "cmd" strings and constant-resolved)
  - ROBOT_RESPONSE / NO_RESPONSE lists → awaits_response + event direction
  - mode→action enum mapping stored in self.extra
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

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

_WS_URI_RE = re.compile(r'"ws://[^"]*:(\d+)"')
_WS_CLASS_RE = re.compile(r'(WebSocketClient|WebSocket|ws_connect|wss://|ws://)', re.I)
_RETROFIT_METHOD_RE = re.compile(r'@(GET|POST|PUT|DELETE|PATCH|HEAD)\("([^"]+)"\)')

# put("cmd", "literal_value")
_CMD_LITERAL_RE = re.compile(r'\.put\s*\(\s*"cmd"\s*,\s*"([^"]+)"\s*\)')
# put("cmd", CONSTANT) or put("cmd", Class.CONSTANT)
_CMD_CONST_RE = re.compile(r'\.put\s*\(\s*"cmd"\s*,\s*(?:\w+\.)?([A-Z_][A-Z0-9_]*)\s*\)')
# Any put("key", value) for field extraction
_FIELD_RE = re.compile(r'\.put\s*\(\s*"([^"]+)"\s*,\s*([^)]+)\)')

# static final String CONST = "value"
_STR_CONST_RE = re.compile(
    r'(?:public|private|protected)?\s*static\s+final\s+String\s+(\w+)\s*=\s*"([^"]+)"'
)
# ROBOT_*_COMMAND_LIST = new ArrayList(Arrays.asList(A, B, C))
_CMD_LIST_RE = re.compile(
    r'(ROBOT_RESPONSE_COMMAND_LIST|ROBOT_NO_RESPONSE_COMMAND_LIST)\s*='
    r'\s*new\s+ArrayList\s*\(\s*Arrays\.asList\s*\(([^)]+)\)\s*\)'
)
_WS_PORT_RE = re.compile(r'(?:WEBSOCKET_PORT|WS_PORT|PORT)\s*=\s*(\d+)')
_UDP_PORT_RE = re.compile(r'(?:SERVER_PORT|UDP_PORT)\s*=\s*(\d+)')
_SERIALIZED_RE = re.compile(
    r'@SerializedName\("([^"]+)"\)\s*(?:private\s+)?(\w+)\s+(\w+);'
)


class ProtocolScanner:
    def __init__(self, apk_out_dir: Path) -> None:
        self._sources = apk_out_dir / "sources"
        self._app_sources: list[Path] = []
        self._str_constants: dict[str, str] = {}   # CONST_NAME → "string_value"
        self._response_cmds: set[str] = set()       # cmds that receive a reply
        self._no_response_cmds: set[str] = set()    # fire-and-forget / push cmds
        self.extra: dict[str, Any] = {}             # caller merges into ProtocolIR.extra

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
            self._app_sources = [
                f for f in self._sources.rglob("*.java")
                if not any(lib in str(f) for lib in (
                    "androidx/", "android/support/", "com/google/", "kotlin/",
                    "okhttp3/", "retrofit2/", "okio/", "com/squareup/",
                ))
            ]

        _LOGGER.info("Scanning %d source files for package %s", len(self._app_sources), app_package)

        self._collect_str_constants()
        self._collect_cmd_lists()
        transport = self._detect_transport()
        discovery = self._detect_discovery()
        auth = self._detect_auth()
        state = self._detect_state_schema()
        commands, events = self._extract_endpoints()
        self._extract_mode_actions()

        return transport, discovery, auth, state, commands, events

    # ── pre-passes ────────────────────────────────────────────────────────────

    def _read(self, path: Path) -> str:
        try:
            return path.read_text(errors="replace")
        except OSError:
            return ""

    def _collect_str_constants(self) -> None:
        for f in self._app_sources:
            src = self._read(f)
            for m in _STR_CONST_RE.finditer(src):
                self._str_constants[m.group(1)] = m.group(2)

    def _collect_cmd_lists(self) -> None:
        """Resolve ROBOT_RESPONSE_COMMAND_LIST and ROBOT_NO_RESPONSE_COMMAND_LIST."""
        for f in self._app_sources:
            src = self._read(f)
            for m in _CMD_LIST_RE.finditer(src):
                list_name = m.group(1)
                const_names = [n.strip() for n in m.group(2).split(",") if n.strip()]
                resolved = {
                    self._str_constants.get(name, name.lower())
                    for name in const_names
                }
                if list_name == "ROBOT_RESPONSE_COMMAND_LIST":
                    self._response_cmds = resolved
                else:
                    self._no_response_cmds = resolved
        if self._response_cmds:
            _LOGGER.info("Response cmds: %s", sorted(self._response_cmds))
        if self._no_response_cmds:
            _LOGGER.info("No-response cmds: %s", sorted(self._no_response_cmds))

    # ── detection passes ──────────────────────────────────────────────────────

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
                # Prefer the known UDP broadcast command name from the no-response list
                broadcast_cmd: str | None = next(
                    (c for c in self._no_response_cmds if "broadcast" in c.lower() or "udp" in c.lower()),
                    None,
                )
                if not broadcast_cmd:
                    m2 = re.search(r'"cmd".*?"([^"]+)"', src)
                    if m2:
                        broadcast_cmd = m2.group(1)
                _LOGGER.info("Discovery: UDP broadcast port=%s cmd=%s", port, broadcast_cmd)
                return DiscoveryMechanism(
                    type=DiscoveryType.UDP_BROADCAST,
                    port=port,
                    broadcast_cmd=broadcast_cmd,
                )
            if "NsdManager" in src:
                return DiscoveryMechanism(type=DiscoveryType.ZEROCONF)

        return DiscoveryMechanism(type=DiscoveryType.NONE)

    def _detect_auth(self) -> AuthScheme:
        grant_access_value = self._str_constants.get("GRANT_ACCESS", "grantAccess")
        for f in self._app_sources:
            src = self._read(f)
            if f'"{grant_access_value}"' in src or grant_access_value in self._str_constants.values():
                fields = [
                    FieldDef(name="uuid", serialized_name="uuid", kind=FieldKind.STRING),
                    FieldDef(name="device_name", serialized_name="device_name", kind=FieldKind.STRING),
                ]
                return AuthScheme(
                    type=AuthType.HANDSHAKE,
                    handshake_cmd=grant_access_value,
                    fields=fields,
                    description="Send grantAccess on WebSocket open; robot responds with state + resultCode",
                )
            if "@Headers" in src and ("Authorization" in src or "X-API-Key" in src):
                return AuthScheme(type=AuthType.API_KEY, description="Static API key in headers")

        return AuthScheme(type=AuthType.NONE)

    def _detect_state_schema(self) -> StateSchema:
        fields: list[FieldDef] = []
        push_cmd: str | None = None
        gin_value = self._str_constants.get("GIN", "gin")

        for f in self._app_sources:
            src = self._read(f)
            if f'"{gin_value}"' in src:
                push_cmd = gin_value
            if any(kw in f.name for kw in ("Robot", "State", "Status")):
                for m in _SERIALIZED_RE.finditer(src):
                    json_name, java_type, field_name = m.group(1), m.group(2), m.group(3)
                    if not any(fd.serialized_name == json_name for fd in fields):
                        fields.append(FieldDef(
                            name=field_name,
                            serialized_name=json_name,
                            kind=_java_type_to_kind(java_type),
                        ))

        if fields:
            _LOGGER.info("State schema: %d fields, push_cmd=%s", len(fields), push_cmd)
        return StateSchema(push_cmd=push_cmd, fields=fields)

    # ── endpoint extraction ───────────────────────────────────────────────────

    def _extract_endpoints(self) -> tuple[list[Endpoint], list[Endpoint]]:
        endpoints_by_cmd: dict[str, Endpoint] = {}

        for f in self._app_sources:
            src = self._read(f)
            class_name = f.stem

            # Literal: put("cmd", "grantAccess")
            for m in _CMD_LITERAL_RE.finditer(src):
                self._register(src, m.group(1), None, class_name, endpoints_by_cmd)

            # Constant-based: put("cmd", MUTE) → resolve to "mute"
            for m in _CMD_CONST_RE.finditer(src):
                const_name = m.group(1)
                cmd_value = self._str_constants.get(const_name)
                if cmd_value:
                    self._register(src, cmd_value, const_name, class_name, endpoints_by_cmd)

            # Retrofit HTTP endpoints
            for m in _RETROFIT_METHOD_RE.finditer(src):
                key = f"{m.group(1)} {m.group(2)}"
                if key not in endpoints_by_cmd:
                    endpoints_by_cmd[key] = Endpoint(
                        cmd=key,
                        transport=TransportType.HTTP_REST,
                        direction=Direction.TO_DEVICE,
                        awaits_response=True,
                        source_class=class_name,
                    )

        # Split by direction: no-response minus user_control → events
        user_control = self._str_constants.get("USER_CONTROL", "user_control")
        event_cmd_names = self._no_response_cmds - {user_control}

        commands: list[Endpoint] = []
        events: list[Endpoint] = []

        for ep in endpoints_by_cmd.values():
            if ep.cmd in event_cmd_names:
                events.append(ep.model_copy(update={"direction": Direction.FROM_DEVICE, "awaits_response": False}))
            else:
                commands.append(ep)

        # Guarantee event entries exist even if scan missed them
        found_event_cmds = {e.cmd for e in events}
        for cmd in event_cmd_names:
            if cmd not in found_event_cmds:
                events.append(Endpoint(
                    cmd=cmd,
                    transport=TransportType.WEBSOCKET,
                    direction=Direction.FROM_DEVICE,
                    awaits_response=False,
                    source_class="RobotApi",
                ))

        _LOGGER.info("Extracted %d commands, %d events", len(commands), len(events))
        return commands, events

    def _register(
        self,
        src: str,
        cmd: str,
        const_name: str | None,
        class_name: str,
        endpoints_by_cmd: dict[str, Endpoint],
    ) -> None:
        """Insert or update endpoint, keeping the entry with more fields."""
        awaits = cmd in self._response_cmds
        fields = _extract_fields_near_cmd(src, cmd, const_name)

        existing = endpoints_by_cmd.get(cmd)
        if existing and len(existing.request_fields) >= len(fields):
            return

        endpoints_by_cmd[cmd] = Endpoint(
            cmd=cmd,
            transport=TransportType.WEBSOCKET,
            direction=Direction.TO_DEVICE,
            awaits_response=awaits,
            request_fields=fields,
            source_class=class_name,
        )

    def _extract_mode_actions(self) -> None:
        """Build mode→action_name dict from if-elif chains and store in self.extra."""
        mode_actions: dict[int, str] = {}
        for f in self._app_sources:
            src = self._read(f)
            if 'put("mode"' not in src and "action_" not in src:
                continue
            pending: str | None = None
            for line in src.splitlines():
                m = re.search(r'action_(\w+)', line)
                if m:
                    pending = m.group(1)
                m2 = re.search(r'\.put\s*\(\s*"mode"\s*,\s*(\d+)\s*\)', line)
                if m2 and pending is not None:
                    mode_actions[int(m2.group(1))] = pending
                    pending = None
        if mode_actions:
            _LOGGER.info("Mode→action enum: %s", mode_actions)
            self.extra["mode_actions"] = mode_actions


# ── helpers ────────────────────────────────────────────────────────────────────

def _extract_fields_near_cmd(src: str, cmd: str, const_name: str | None) -> list[FieldDef]:
    """Return the other put() fields in the ~600-char block after the cmd put()."""
    fields: list[FieldDef] = []
    # Prefer searching by constant name if available (more precise in source)
    search_terms: list[str] = []
    if const_name:
        search_terms.append(f'"cmd", {const_name}')
        search_terms.append(f'"cmd", {const_name})')
    search_terms.append(f'"cmd", "{cmd}"')

    for term in search_terms:
        idx = src.find(term)
        if idx != -1:
            block = src[idx: idx + 600]
            seen: set[str] = set()
            for m in _FIELD_RE.finditer(block):
                fname = m.group(1)
                if fname in ("cmd", "seq") or fname in seen:
                    continue
                seen.add(fname)
                fields.append(FieldDef(
                    name=fname,
                    serialized_name=fname,
                    kind=_infer_field_kind(m.group(2).strip()),
                ))
            return fields
    return fields


def _java_type_to_kind(java_type: str) -> FieldKind:
    t = java_type.lower()
    if t == "string":
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


def _infer_field_kind(rhs: str) -> FieldKind:
    if rhs in ("true", "false") or rhs.startswith("enable"):
        return FieldKind.BOOLEAN
    if re.match(r'^-?\d+$', rhs):
        return FieldKind.INTEGER
    if rhs.startswith('"'):
        return FieldKind.STRING
    return FieldKind.STRING
