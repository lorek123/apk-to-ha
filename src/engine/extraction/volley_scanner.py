# SPDX-License-Identifier: MIT
"""P2-1b — Volley HTTP request scanner.

Finds ``new JsonObjectRequest(method, url, body, …)`` (and StringRequest,
JsonArrayRequest, and the app's own Request subclasses) in first-party code and
turns each into an HTTP endpoint:

  method  literal 0/1/2/3/… → GET/POST/PUT/DELETE/…; a variable → "REQUEST"
          (reported, not guessed)
  path    the URL concatenation as a template: string literals kept, the base
          URL dropped, other expressions become {placeholders}
          (``this.url + "api/" + getUsername() + "/groups"`` → ``/api/{username}/groups``)
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from pathlib import Path

from ..ir.models import Direction, Endpoint, TransportType
from . import confidence
from .app_sources import app_source_files

_LOGGER = logging.getLogger(__name__)

_VOLLEY_BASES = ("JsonObjectRequest", "JsonArrayRequest", "StringRequest", "JsonRequest")
_SUBCLASS_RE = re.compile(r"\bclass\s+(\w+)\s+extends\s+(\w+)")
# Volley's Request.Method constants
_METHODS = {"0": "GET", "1": "POST", "2": "PUT", "3": "DELETE", "4": "HEAD", "7": "PATCH"}
# Identifiers that hold the device's base URL; dropped from the path template.
_BASE_URL_NAME = re.compile(r"(?:^|\.)(?:url|baseUrl|base_url|mUrl|host|address|ip)$", re.I)
_STRING_LITERAL = re.compile(r'^"((?:[^"\\]|\\.)*)"$')
# A method argument: Volley's int constant, or R8's short local for it (i, i2).
_METHOD_ARG = re.compile(r"^(?:\d+|i\d*)$")
# R8 outlines string concatenation into synthetic helpers:
#   Foo$$ExternalSyntheticOutline0.m137m(a, b)  ==  a + b
_OUTLINED_CONCAT = re.compile(r"^[\w$.]*ExternalSyntheticOutline\d*\.\w+\s*\(")
_IDENT = re.compile(r"^[A-Za-z_]\w*$")


def _resolve_locals(src: str, pos: int, expr: str, depth: int = 3) -> str:
    """Replace a bare local variable with its nearest preceding assignment's expression."""
    expr = expr.strip()
    if depth == 0 or not _IDENT.match(expr) or _BASE_URL_NAME.search(expr):
        return expr
    assigns = list(re.finditer(rf"\b{re.escape(expr)}\s*=\s*([^;]+);", src[:pos]))
    if not assigns:
        return expr
    return _resolve_locals(src, assigns[-1].start(), assigns[-1].group(1), depth - 1)


def scan(apk_out_dir: Path, app_package: str) -> list[Endpoint]:
    """HTTP endpoints for every Volley request constructed in first-party code."""
    sources = apk_out_dir / "sources"
    if not sources.exists():
        return []
    texts = {f: f.read_text(errors="replace") for f in app_source_files(sources, app_package)}
    request_types = _request_types(texts.values())
    ctor = re.compile(r"\bnew\s+(" + "|".join(map(re.escape, request_types)) + r")\s*\(")

    endpoints: dict[str, Endpoint] = {}
    for path, src in texts.items():
        for m in ctor.finditer(src):
            args = split_args(src, m.end())
            # Volley's own classes take (method, url, …); app subclasses often (url, …).
            if len(args) >= 2 and _METHOD_ARG.match(args[0].strip()):
                method, url_expr = _METHODS.get(args[0].strip(), "REQUEST"), args[1]
            elif args:
                method, url_expr = "REQUEST", args[0]
            else:
                continue
            template = url_template(_resolve_locals(src, m.start(), url_expr))
            if template is None:
                continue
            cmd = f"{method} {template}"
            endpoints.setdefault(
                cmd,
                Endpoint(
                    cmd=cmd,
                    transport=TransportType.HTTP_REST,
                    direction=Direction.TO_DEVICE,
                    awaits_response=True,
                    source_class=path.stem.split("$")[0],
                    confidence=confidence.score(
                        confidence.NAME_REQUEST_CALL, confidence.FIELDS_NONE
                    ),
                ),
            )
    # An unknown method ("REQUEST") adds nothing when the same path is seen with one.
    known = {cmd.split(" ", 1)[1] for cmd in endpoints if not cmd.startswith("REQUEST ")}
    result = [
        ep for cmd, ep in endpoints.items()
        if not (cmd.startswith("REQUEST ") and cmd.split(" ", 1)[1] in known)
    ]  # fmt: skip
    if result:
        _LOGGER.info("volley_scanner: %d endpoints", len(result))
    return result


def _request_types(sources: Iterable[str]) -> list[str]:
    """Volley request classes plus first-party subclasses of them (transitively)."""
    types = set(_VOLLEY_BASES)
    extends = [m.groups() for src in sources for m in _SUBCLASS_RE.finditer(src)]
    changed = True
    while changed:
        changed = False
        for sub, base in extends:
            if base in types and sub not in types:
                types.add(sub)
                changed = True
    return sorted(types, key=len, reverse=True)


def split_args(src: str, start: int) -> list[str]:
    """Top-level comma-separated arguments of the call whose '(' ends at *start*."""
    args: list[str] = []
    depth, current, in_str, escape = 0, [], False, False
    for ch in src[start:]:
        if in_str:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append("".join(current).strip())
                return args
            depth -= 1
        elif ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    return args


def url_template(expr: str) -> str | None:
    """Path template for a URL concatenation, or None if no literal path part."""
    parts = _split_concat(expr)
    pieces: list[str] = []
    saw_literal = False
    for i, part in enumerate(parts):
        lit = _STRING_LITERAL.match(part)
        if lit:
            text = lit.group(1)
            if re.match(r"https?://", text):  # absolute URL: keep only its path
                text = re.sub(r"^https?://[^/]*", "", text)
            pieces.append(text)
            saw_literal = saw_literal or bool(text.strip("/"))
        elif i == 0:
            continue  # a leading dynamic piece is the device's base URL
        else:
            pieces.append("{" + _placeholder(part) + "}")
    if not saw_literal:
        return None
    path = "/" + re.sub(r"/{2,}", "/", "".join(pieces).split("?", 1)[0]).lstrip("/")
    # Needs at least one fixed segment: "/{obj}" says nothing about the API.
    if not any(seg and not re.fullmatch(r"\{\w+\}", seg) for seg in path.split("/")):
        return None
    return path


def _split_concat(expr: str) -> list[str]:
    """Split on top-level '+' (outside strings and parentheses); expand outlined concats."""
    expr = expr.strip()
    if _OUTLINED_CONCAT.match(expr):
        return [p for arg in split_args(expr, expr.index("(") + 1) for p in _split_concat(arg)]
    parts, depth, current, in_str, escape = [], 0, [], False, False
    for ch in expr:
        if in_str:
            current.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "+" and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    parts.append("".join(current).strip())
    return [p for p in parts if p]


def _placeholder(expr: str) -> str:
    """Readable name for a dynamic URL piece: getUsername() → username, this.id → id."""
    expr = expr.strip()
    getter = re.search(r"\bget([A-Z]\w*)\s*\(\s*\)\s*$", expr)
    if getter:
        name = getter.group(1)
        return name[0].lower() + name[1:]
    ident = re.findall(r"[A-Za-z_]\w*", expr)
    return ident[-1] if ident else "value"
