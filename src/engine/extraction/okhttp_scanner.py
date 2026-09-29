# SPDX-License-Identifier: MIT
"""P2-1c — OkHttp request scanner (hand-rolled clients, no Retrofit).

Three shapes, all in first-party code:

1. Direct builder calls:
       new Request.Builder().url(this.baseUrl + "/status").get().build()
   → ``GET /status`` (method from the builder chain; default GET).
2. App wrappers that build the request from a *parameter*:
       Object post(String path, Map body) { … Request.Builder().url(this.baseUrl + path).post(…) … }
   and their call sites
       post("/goto", MapsKt.mapOf(TuplesKt.to("az", Double.valueOf(az)), …))
   → ``POST /goto`` with typed request fields from the Kotlin map literal.
3. WebSocket streams: ``newWebSocket(new Request.Builder().url(base + "/ws/status")…)``
   → a FROM_DEVICE endpoint ``WS /ws/status``.

URL expressions reuse the Volley scanner's template logic.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from ..ir.models import Direction, Endpoint, FieldDef, FieldKind, TransportType
from . import confidence
from .app_sources import app_source_files
from .volley_scanner import _resolve_locals, split_args, url_template

_LOGGER = logging.getLogger(__name__)

_BUILDER_URL = re.compile(r"new\s+Request\.Builder\(\)\s*\.url\s*\(")
_CHAIN_METHOD = re.compile(r"\.(get|head|post|put|patch|delete)\s*\(")
_NEW_WEBSOCKET = re.compile(r"newWebSocket\s*\(\s*$")
_METHOD_DECL = re.compile(
    r"^[ \t]*(?:(?:public|private|protected|static|final|synchronized)\s+)*"
    r"[\w.<>\[\], ]+?\s+([\w$]+)\s*\(([^)]*)\)\s*(?:throws\s+[\w., ]+)?\{",
    re.MULTILINE,
)
# Kotlin map literal entries: TuplesKt.to("az", Double.valueOf(az)) / TuplesKt.m82to("axis", axis)
_MAP_ENTRY = re.compile(r'TuplesKt\.\w+\s*\(\s*"([^"]+)"\s*,\s*([^)]*\)?)')
_BOXED_KIND = {
    "Double": FieldKind.NUMBER,
    "Float": FieldKind.NUMBER,
    "Integer": FieldKind.INTEGER,
    "Long": FieldKind.INTEGER,
    "Short": FieldKind.INTEGER,
    "Boolean": FieldKind.BOOLEAN,
}


@dataclass
class _Wrapper:
    method: str  # HTTP method the wrapper sends
    name: str  # Java method name (as decompiled)


def scan(apk_out_dir: Path, app_package: str) -> list[Endpoint]:
    sources = apk_out_dir / "sources"
    if not sources.exists():
        return []
    texts = {f: f.read_text(errors="replace") for f in app_source_files(sources, app_package)}
    texts = {f: t for f, t in texts.items() if "Request.Builder" in t or "Request$Builder" in t}

    endpoints: dict[str, Endpoint] = {}
    wrappers: list[_Wrapper] = []

    def add(ep: Endpoint) -> None:
        existing = endpoints.get(ep.cmd)
        if existing is None or len(ep.request_fields) > len(existing.request_fields):
            endpoints[ep.cmd] = ep

    for path, src in texts.items():
        cls = path.stem.split("$")[0]
        for m in _BUILDER_URL.finditer(src):
            args = split_args(src, m.end())
            if not args:
                continue
            chain = _builder_chain(src, m.start(), m.end())
            template = url_template(_resolve_locals(src, m.start(), args[0]))
            is_ws = bool(_NEW_WEBSOCKET.search(src[max(0, m.start() - 40) : m.start()]))
            if is_ws:
                if template:
                    add(_endpoint(f"WS {template}", cls, TransportType.WEBSOCKET, stream=True))
                continue
            verb = _chain_method(chain)
            if template:
                add(_endpoint(f"{verb} {template}", cls, TransportType.HTTP_REST))
            else:
                decl = _enclosing_method(src, m.start())
                if decl:  # URL built from a parameter: an app-level request wrapper
                    wrappers.append(_Wrapper(method=verb, name=decl))

    # Call sites of the wrappers: path literal + optional Kotlin map body.
    for wrapper in wrappers:
        call = _call_pattern(wrapper.name)
        for path, src in texts.items():
            cls = path.stem.split("$")[0]
            for m in call.finditer(src):
                if _is_declaration(src, m.start()):
                    continue
                args = split_args(src, m.end())
                template = next((t for a in args if (t := url_template(a))), None)
                if template is None:
                    continue
                fields = [f for a in args if "mapOf" in a for f in _map_fields(a)]
                add(_endpoint(f"{wrapper.method} {template}", cls, TransportType.HTTP_REST, fields))

    result = list(endpoints.values())
    if result:
        _LOGGER.info("okhttp_scanner: %d endpoints (%d wrappers)", len(result), len(wrappers))
    return result


def _endpoint(
    cmd: str,
    cls: str,
    transport: TransportType,
    fields: list[FieldDef] | None = None,
    stream: bool = False,
) -> Endpoint:
    return Endpoint(
        cmd=cmd,
        transport=transport,
        direction=Direction.FROM_DEVICE if stream else Direction.TO_DEVICE,
        awaits_response=not stream,
        request_fields=fields or [],
        source_class=cls,
        confidence=confidence.score(
            confidence.NAME_REQUEST_CALL,
            confidence.FIELDS_TYPED if fields else confidence.FIELDS_NONE,
        ),
    )


def _builder_chain(src: str, start: int, url_end: int) -> str:
    """Text where the builder's HTTP method is set.

    Usually the rest of the statement; when the builder is stored in a variable
    (``Request.Builder b = new Request.Builder().url(…); … b.post(…)``), the calls on
    that variable up to the end of the enclosing method.
    """
    stmt_end = src.find(";", url_end)
    stmt = src[url_end : stmt_end if stmt_end != -1 else len(src)]
    if _CHAIN_METHOD.search(stmt):
        return stmt
    line_start = src.rfind("\n", 0, start) + 1
    var = re.search(r"(\w+)\s*=\s*$", src[line_start:start])
    if var is None:
        return stmt
    nxt = _METHOD_DECL.search(src, url_end)
    body = src[url_end : nxt.start() if nxt else len(src)]
    calls = re.findall(
        rf"\b{re.escape(var.group(1))}\s*(\.(?:get|head|post|put|patch|delete)\s*\()", body
    )
    return "".join(calls)


def _call_pattern(name: str) -> re.Pattern[str]:
    """Call sites of *name*, including its Kotlin default-args twin.

    JADX renames mangled Kotlin names with a numbered prefix, and the $default
    variant gets a different number: m6120postgIAlus / m6121postgIAlus$default.
    """
    renamed = re.fullmatch(r"m\d+(\w+)", name)
    stem = rf"m\d+{re.escape(renamed.group(1))}" if renamed else re.escape(name)
    return re.compile(rf"\b{stem}(?:\$default)?\s*\(")


def _chain_method(chain: str) -> str:
    """HTTP method from a Request.Builder chain after .url(…); OkHttp defaults to GET."""
    m = _CHAIN_METHOD.search(chain)
    return m.group(1).upper() if m else "GET"


def _enclosing_method(src: str, pos: int) -> str | None:
    decls = [d for d in _METHOD_DECL.finditer(src[:pos])]
    return decls[-1].group(1) if decls else None


def _is_declaration(src: str, pos: int) -> bool:
    line_start = src.rfind("\n", 0, pos) + 1
    return bool(_METHOD_DECL.match(src[line_start : src.find("{", pos) + 1]))


def _map_fields(expr: str) -> list[FieldDef]:
    """Typed fields from a Kotlin mapOf(TuplesKt.to("k", Boxed.valueOf(v)), …) literal."""
    fields: list[FieldDef] = []
    for key, value in _MAP_ENTRY.findall(expr):
        boxed = re.match(r"\s*(\w+)\.valueOf\s*\(", value)
        kind = _BOXED_KIND.get(boxed.group(1), FieldKind.STRING) if boxed else FieldKind.STRING
        fields.append(FieldDef(name=key, serialized_name=key, kind=kind))
    return fields


# Hand-parsed JSON: Object obj = map.get("az"); Double d = obj instanceof Double ? … : null;
_MAP_GET_TYPED = re.compile(
    r'(\w+)\s*=\s*\w+\.get\(\s*"([^"]+)"\s*\);\s*\w+\s+\w+\s*=\s*\1\s+instanceof\s+(\w+)'
)
_MIN_STATE_KEYS = 3


def json_map_state(apk_out_dir: Path, app_package: str) -> list[FieldDef]:
    """State fields from the largest hand-parsed JSON object in first-party code.

    Apps without annotated models read status JSON key by key
    (``map.get("temp_c")`` then ``instanceof Double``); the method with the most
    typed keys is taken as the device state.
    """
    sources = apk_out_dir / "sources"
    if not sources.exists():
        return []
    best: list[FieldDef] = []
    for f in app_source_files(sources, app_package):
        src = f.read_text(errors="replace")
        decls = list(_METHOD_DECL.finditer(src))
        bounds = [d.start() for d in decls] + [len(src)]
        for start, end in pairwise(bounds):
            fields: dict[str, FieldDef] = {}
            for _, key, java_type in _MAP_GET_TYPED.findall(src[start:end]):
                kind = _BOXED_KIND.get(java_type, FieldKind.STRING)
                fields.setdefault(key, FieldDef(name=key, serialized_name=key, kind=kind))
            if len(fields) > len(best):
                best = list(fields.values())
    return best if len(best) >= _MIN_STATE_KEYS else []
