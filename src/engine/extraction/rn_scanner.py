# SPDX-License-Identifier: MIT
"""P1-6 — React Native protocol extraction.

Finds index.android.bundle (Metro plain-JS or Hermes bytecode), extracts:
  - fetch() / axios.*() HTTP call sites → REST endpoints
  - new WebSocket(url) → transport URL
  - JSON objects with a `cmd` key → WS command names (same protocol as Native)
  - URL-like string constants → base URL / port hints

Bronze-tier quality: not all call sites will be found in minified code, but
the most common patterns (direct URL literals, axios base config, WS ctor) are
detected reliably.
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

# Hermes bytecode magic: first 4 bytes (version-independent prefix)
_HERMES_MAGIC = b"\xc6\x1f\xbc"

# Regexes applied to the raw bundle text as a fast/fallback path
_WS_URL_RE = re.compile(r"""["'`](wss?://[^"'`\s]+)["'`]""")
_WS_URL_BARE_RE = re.compile(r"""\b(wss?://[^\s"'`\x00-\x1f]+)""")
_HTTP_URL_RE = re.compile(r"""["'`](https?://[^"'`\s]+)["'`]""")
_PATH_RE = re.compile(r"""["'`](/[a-zA-Z0-9_/.-]{3,})["'`]""")
_CMD_STR_RE = re.compile(r"""['"](cmd)['"]\s*:\s*['"]([\w-]+)['"]""")
_WS_PORT_RE = re.compile(r"""['"](ws[s]?://[^"']*?:(\d{4,5}))["']""")
_BASE_URL_RE = re.compile(
    r"""(?:BASE_URL|baseURL|baseUrl|BASE|SERVER_URL)\s*[:=]\s*["'`]([^"'`]+)["'`]"""
)


class RNScanner:
    """Extract protocol IR from a React Native APK output directory."""

    def __init__(self, apk_out_dir: Path) -> None:
        self._root = apk_out_dir

    def scan(
        self,
        package_name: str,
    ) -> tuple[
        TransportContract,
        DiscoveryMechanism,
        AuthScheme,
        StateSchema,
        list[Endpoint],
        list[Endpoint],
    ]:
        bundle_path = self._find_bundle()
        if bundle_path is None:
            _LOGGER.warning("rn_scanner: no bundle found under %s", self._root)
            return _defaults()

        text = _read_bundle(bundle_path)
        _LOGGER.info("rn_scanner: bundle size=%d chars (%s)", len(text), bundle_path.name)

        # ── extract raw signals ────────────────────────────────────────────────
        ws_urls = list(dict.fromkeys(_WS_URL_RE.findall(text) + _WS_URL_BARE_RE.findall(text)))
        http_urls = list(dict.fromkeys(_HTTP_URL_RE.findall(text)))
        base_urls = list(dict.fromkeys(_BASE_URL_RE.findall(text)))
        cmd_names = list(dict.fromkeys(_CMD_STR_RE.findall(text)))  # [(key, value), ...]
        cmd_names_only = [v for _, v in cmd_names]

        # ── AST-level extraction (best-effort, tolerant) ──────────────────────
        try:
            import esprima

            ast_data = _ast_extract(esprima.parseScript(text, tolerant=True))
            fetch_calls = ast_data["fetch_calls"]
            ws_ctors = ast_data["ws_ctors"]
            cmd_literals = ast_data["cmd_literals"]
            field_maps = ast_data["field_maps"]
        except Exception as exc:
            _LOGGER.debug("rn_scanner: AST parse failed (%s) — regex only", exc)
            fetch_calls = []
            ws_ctors = list(ws_urls)
            cmd_literals = cmd_names_only
            field_maps = {}

        # ── transport ─────────────────────────────────────────────────────────
        all_ws = list(dict.fromkeys(ws_ctors + ws_urls))
        if all_ws:
            port = _port_from_url(all_ws[0]) or 8887
            transport: TransportContract = TransportContract(
                type=TransportType.WEBSOCKET,
                port=port,
                url_template=all_ws[0] if "{host}" not in all_ws[0] else all_ws[0],
            )
        elif fetch_calls or http_urls:
            port = _port_from_url((fetch_calls + http_urls)[0]) or 80
            transport = TransportContract(type=TransportType.HTTP_REST, port=port)
        else:
            transport = TransportContract(type=TransportType.HTTP_REST, port=80)

        # ── discovery (RN apps rarely use UDP broadcast; default NONE) ────────
        discovery = DiscoveryMechanism(type=DiscoveryType.NONE)

        # ── auth ──────────────────────────────────────────────────────────────
        auth_cmd = _detect_auth_cmd(cmd_literals)
        if auth_cmd:
            auth: AuthScheme = AuthScheme(type=AuthType.HANDSHAKE, handshake_cmd=auth_cmd)
        elif any(_is_auth_url(u) for u in fetch_calls + http_urls):
            auth = AuthScheme(type=AuthType.API_KEY)
        else:
            auth = AuthScheme(type=AuthType.NONE)

        # ── commands from WS cmd literals ─────────────────────────────────────
        _SKIP = {"ping", "pong", "connect", "disconnect", "subscribe", "unsubscribe"}
        commands: list[Endpoint] = []
        events: list[Endpoint] = []

        for cmd in cmd_literals:
            if cmd in _SKIP or cmd == auth_cmd:
                continue
            fields = [
                FieldDef(name=k, kind=_infer_kind(v))
                for k, v in (field_maps.get(cmd) or {}).items()
                if k != "cmd"
            ]
            commands.append(
                Endpoint(
                    cmd=cmd,
                    transport=transport.type,
                    direction=Direction.TO_DEVICE,
                    request_fields=fields,
                    confidence=0.65,
                )
            )

        # ── commands from fetch/axios calls ───────────────────────────────────
        for call in fetch_calls:
            cmd = _path_to_cmd(call)
            if not cmd or any(e.cmd == cmd for e in commands):
                continue
            method = "GET"
            if isinstance(call, dict):
                method = call.get("method", "GET").upper()
                call = call.get("url", call)
            direction = Direction.FROM_DEVICE if method == "GET" else Direction.TO_DEVICE
            commands.append(
                Endpoint(
                    cmd=cmd,
                    transport=TransportType.HTTP_REST,
                    direction=direction,
                    confidence=0.6,
                )
            )

        # ── state (empty for Bronze; populated from responses in P2-1 analogue) ──
        state = StateSchema()

        return transport, discovery, auth, state, commands, events

    def _find_bundle(self) -> Path | None:
        for candidate in self._root.rglob("index.android.bundle"):
            return candidate
        return None


# ── bundle reading ────────────────────────────────────────────────────────────


def _read_bundle(path: Path) -> str:
    """Return bundle as text. Handles Hermes bytecode by extracting string literals."""
    raw = path.read_bytes()
    if raw[:3] == _HERMES_MAGIC:
        _LOGGER.info("rn_scanner: Hermes bytecode detected — extracting strings")
        return _hermes_extract_strings(raw)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _hermes_extract_strings(data: bytes) -> str:
    """Extract printable ASCII strings ≥6 chars from Hermes bytecode.

    The Hermes string table is structured but parsing the full binary format is
    complex. For Bronze tier we scan for runs of printable ASCII which captures
    all string literals with acceptable false-positive rate.
    """
    strings: list[str] = []
    buf: list[int] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            buf.append(b)
        else:
            if len(buf) >= 6:
                s = bytes(buf).decode("ascii")
                strings.append(s)
            buf = []
    if len(buf) >= 6:
        strings.append(bytes(buf).decode("ascii"))
    return "\n".join(strings)


# ── AST extraction ────────────────────────────────────────────────────────────


def _ast_extract(tree: Any) -> dict[str, Any]:
    """Walk esprima AST and collect fetch calls, WS constructors, cmd literals."""
    fetch_calls: list[str | dict[str, Any]] = []
    ws_ctors: list[str] = []
    cmd_literals: list[str] = []
    field_maps: dict[str, dict[str, Any]] = {}

    def _lit(node: Any) -> str | None:
        if hasattr(node, "type") and node.type == "Literal":
            return str(node.value) if node.value is not None else None
        return None

    def _walk(node: Any) -> None:
        if node is None or not hasattr(node, "type"):
            return

        if node.type == "CallExpression":
            callee = node.callee
            args = list(node.arguments) if node.arguments else []

            # fetch(url) / fetch(url, {method: ..., body: ...})
            if hasattr(callee, "name") and callee.name == "fetch" and args:
                url = _lit(args[0])
                method = "POST"
                if len(args) > 1 and hasattr(args[1], "properties"):
                    for prop in args[1].properties:
                        if hasattr(prop, "key") and _prop_key(prop) == "method":
                            method = _lit(prop.value) or method
                if url:
                    fetch_calls.append({"url": url, "method": method})

            # axios.get/post/put/delete/patch(url, ...)
            if (
                callee.type == "MemberExpression"
                and hasattr(callee.object, "name")
                and callee.object.name == "axios"
                and args
            ):
                url = _lit(args[0])
                http_method = getattr(callee.property, "name", "post").upper()
                if url:
                    fetch_calls.append({"url": url, "method": http_method})

        # new WebSocket(url)
        if node.type == "NewExpression":
            callee = node.callee
            args = list(node.arguments) if node.arguments else []
            if hasattr(callee, "name") and callee.name == "WebSocket" and args:
                url = _lit(args[0])
                if url:
                    ws_ctors.append(url)

        # ObjectExpression with cmd key → command literal
        if node.type == "ObjectExpression" and node.properties:
            obj: dict[str, Any] = {}
            for prop in node.properties:
                key = _prop_key(prop)
                val = _lit(prop.value) if hasattr(prop, "value") else None
                if key:
                    obj[key] = val
            if obj.get("cmd"):
                cmd = obj["cmd"]
                cmd_literals.append(cmd)
                field_maps[cmd] = {k: v for k, v in obj.items() if v is not None}

        # Recurse into all child nodes
        for attr in (
            "body",
            "declarations",
            "expression",
            "consequent",
            "alternate",
            "callee",
            "arguments",
            "properties",
            "elements",
            "left",
            "right",
            "object",
            "property",
            "init",
            "test",
            "update",
            "argument",
        ):
            child = getattr(node, attr, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    _walk(item)
            else:
                _walk(child)

    _walk(tree)
    return {
        "fetch_calls": list(
            dict.fromkeys(c["url"] if isinstance(c, dict) else c for c in fetch_calls)
        ),
        "ws_ctors": list(dict.fromkeys(ws_ctors)),
        "cmd_literals": list(dict.fromkeys(cmd_literals)),
        "field_maps": field_maps,
        "fetch_calls_full": fetch_calls,
    }


# ── helpers ───────────────────────────────────────────────────────────────────


def _prop_key(prop: Any) -> str | None:
    key = getattr(prop, "key", None)
    if key is None:
        return None
    if hasattr(key, "name"):
        return str(key.name)
    if hasattr(key, "value"):
        return str(key.value)
    return None


def _port_from_url(url: str) -> int | None:
    m = re.search(r":(\d{2,5})(?:/|$)", url)
    return int(m.group(1)) if m else None


def _path_to_cmd(url: str | dict[str, Any]) -> str | None:
    if isinstance(url, dict):
        url = str(url.get("url", ""))
    path = re.sub(r"https?://[^/]+", "", url).split("?")[0].rstrip("/")
    if not path:
        return None
    last = path.rsplit("/", 1)[-1]
    # Skip pure-digit segments (IDs) and very short segments
    if last.isdigit() or len(last) < 2:
        return None
    # camelCase-ify path segments like "device-control" → "deviceControl"
    parts = re.split(r"[-_]", last)
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _is_auth_url(url: str | dict[str, Any]) -> bool:
    if isinstance(url, dict):
        url = str(url.get("url", ""))
    return bool(re.search(r"auth|login|token|session", str(url), re.I))


def _detect_auth_cmd(cmd_literals: list[str]) -> str | None:
    for cmd in cmd_literals:
        if re.search(r"auth|login|grant|handshake|connect", cmd, re.I):
            return cmd
    return None


def _infer_kind(value: Any) -> FieldKind:
    if isinstance(value, bool):
        return FieldKind.BOOLEAN
    if isinstance(value, int):
        return FieldKind.INTEGER
    if isinstance(value, float):
        return FieldKind.NUMBER
    return FieldKind.STRING


def _defaults() -> tuple[
    TransportContract, DiscoveryMechanism, AuthScheme, StateSchema, list[Any], list[Any]
]:
    return (
        TransportContract(type=TransportType.HTTP_REST, port=80),
        DiscoveryMechanism(type=DiscoveryType.NONE),
        AuthScheme(type=AuthType.NONE),
        StateSchema(),
        [],
        [],
    )
