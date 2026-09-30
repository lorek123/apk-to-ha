# SPDX-License-Identifier: MIT
"""P5 — Home Assistant actions for commands no entity can drive.

A button can't supply parameters and can't show a reply, so commands like
``POST /mkdir {name, path}`` or ``MUTATION StopVm(id)`` and queries like
``GET /api/files?path=`` become actions (``inkcast.mkdir``) instead:

  - one voluptuous schema per action, from the command's request fields
  - a ``config_entry_id`` field picks the device (actions are registered once,
    in async_setup, per HA's action-setup rule)
  - queries return the device's reply (SupportsResponse.ONLY); push transports
    (WebSocket) can't correlate replies, so their queries stay unmapped
  - services.yaml selectors and strings.json names/descriptions for the UI
"""

from __future__ import annotations

import keyword
import re
from typing import Any

from ..ir.models import Endpoint, FieldDef, FieldKind, TransportType

# Transports whose SDK can send a parameterised command (BLE characteristics can't).
_ACTION_TRANSPORTS = frozenset(
    {TransportType.HTTP_REST, TransportType.GRAPHQL, TransportType.WEBSOCKET}
)
# Transports that can return a reply to the caller.
_REPLY_TRANSPORTS = frozenset({TransportType.HTTP_REST, TransportType.GRAPHQL})
# SDK client attributes an action method must not shadow.
_RESERVED = frozenset(
    {"connect", "disconnect", "host", "get_state", "send_command", "set_mode", "register_callback"}
)
_SECRET = re.compile(r"pass(word)?|pw$|_pw|secret|token|api_?key", re.IGNORECASE)
# Path segments that don't name the operation: /api/v1/files → files.
_NOISE_SEGMENT = re.compile(r"^(?:api|rest|v\d+)$", re.IGNORECASE)
_PATH_PARAM = re.compile(r"\{(\w+)\}")

_SCHEMA = {
    FieldKind.STRING: "cv.string",
    FieldKind.INTEGER: "vol.Coerce(int)",
    FieldKind.NUMBER: "vol.Coerce(float)",
    FieldKind.BOOLEAN: "cv.boolean",
    FieldKind.ENUM: "cv.string",
    FieldKind.OBJECT: "dict",
    FieldKind.ARRAY: "list",
}
# Test values per kind (the generated runtime tests call each action with these).
_SAMPLE: dict[FieldKind, Any] = {
    FieldKind.STRING: "test",
    FieldKind.INTEGER: 1,
    FieldKind.NUMBER: 1.5,
    FieldKind.BOOLEAN: True,
    FieldKind.ENUM: "test",
    FieldKind.OBJECT: {"key": "value"},
    FieldKind.ARRAY: ["value"],
}
_PY_TYPE = {
    FieldKind.STRING: "str",
    FieldKind.INTEGER: "int",
    FieldKind.NUMBER: "float",
    FieldKind.BOOLEAN: "bool",
    FieldKind.ENUM: "str",
    FieldKind.OBJECT: "dict[str, Any]",
    FieldKind.ARRAY: "list[Any]",
}


def _snake(name: str) -> str:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "value"


def _human(slug: str) -> str:
    return slug.replace("_", " ").capitalize()


def _selector(f: FieldDef, arg: str) -> dict[str, Any]:
    if f.enum_values:
        return {"select": {"options": [str(v) for v in f.enum_values]}}
    match f.kind:
        case FieldKind.INTEGER:
            return {"number": {"mode": "box", "step": 1}}
        case FieldKind.NUMBER:
            return {"number": {"mode": "box", "step": "any"}}
        case FieldKind.BOOLEAN:
            return {"boolean": {}}
        case FieldKind.OBJECT | FieldKind.ARRAY:
            return {"object": {}}
        case _:
            return {"text": {"type": "password"}} if _SECRET.search(arg) else {"text": {}}


def _schema(f: FieldDef) -> str:
    if f.enum_values:
        return f"vol.In({[str(v) for v in f.enum_values]!r})"
    return _SCHEMA[f.kind]


def _http_location(f: FieldDef, method: str, path_params: set[str]) -> str:
    if f.location:
        return f.location
    if f.name in path_params:
        return "path"
    return "query" if method in ("GET", "HEAD", "DELETE") else "json"


def _base_name(ep: Endpoint) -> tuple[str, str | None]:
    """(action name, HTTP method or None) for an endpoint."""
    verb, _, rest = ep.cmd.partition(" ")
    if ep.transport == TransportType.HTTP_REST:
        fixed = [
            s
            for s in rest.split("/")
            if s and not _PATH_PARAM.fullmatch(s) and not _NOISE_SEGMENT.match(s)
        ]
        return _snake("_".join(fixed)) or "root", verb
    if ep.transport == TransportType.GRAPHQL:
        return _snake(rest), None
    return _snake(ep.cmd), None


def build(
    candidates: list[tuple[Endpoint, list[FieldDef], bool]], domain: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Actions for (endpoint, params, is_query) candidates, plus the ones left unmapped.

    *params* are the endpoint's required parameters (path placeholders included),
    as the entity mapping computed them; optional request fields are added here.
    """
    actions: list[dict[str, Any]] = []
    unmapped: list[dict[str, str]] = []
    named: list[tuple[str, str | None, Endpoint, list[FieldDef], bool]] = []
    for ep, params, is_query in candidates:
        if ep.transport not in _ACTION_TRANSPORTS:
            continue
        if is_query and ep.transport not in _REPLY_TRANSPORTS:
            unmapped.append(
                {"cmd": ep.cmd, "reason": "query over a push transport: no reply to return"}
            )
            continue
        name, method = _base_name(ep)
        named.append((name, method, ep, params, is_query))

    # GET /api/settings and POST /api/settings: prefix the verb on every clash.
    counts: dict[str, int] = {}
    for name, *_ in named:
        counts[name] = counts.get(name, 0) + 1
    used: set[str] = set()
    for name, method, ep, params, is_query in named:
        if counts[name] > 1 and method:
            name = f"{method.lower()}_{name}"
        if name in _RESERVED or keyword.iskeyword(name):
            name = f"do_{name}"
        while name in used:
            name += "_2"
        used.add(name)
        actions.append(_action(name, ep, params, is_query, domain))
    return actions, unmapped


def _action(
    name: str, ep: Endpoint, params: list[FieldDef], is_query: bool, domain: str
) -> dict[str, Any]:
    verb, _, rest = ep.cmd.partition(" ")
    http = ep.transport == TransportType.HTTP_REST
    path_params = set(_PATH_PARAM.findall(rest)) if http else set()
    required = {f.name for f in params}
    optional = [f for f in ep.request_fields if f.name not in required and not f.required]
    fields: list[dict[str, Any]] = []
    seen_args: set[str] = {"config_entry_id"}
    for f in [*params, *optional]:
        arg = _snake(f.name)
        if keyword.iskeyword(arg) or arg in ("self", "config_entry_id"):
            arg += "_"
        if arg in seen_args:
            continue
        seen_args.add(arg)
        fields.append(
            {
                "arg": arg,
                "wire": f.serialized_name or f.name,
                "name": _human(arg),
                "required": f.name in required,
                "py_type": _PY_TYPE[f.kind],
                "schema": _schema(f),
                "selector": _selector(f, arg),
                "location": _http_location(f, verb, path_params) if http else None,
                "description": f.description or f"Value for `{f.serialized_name or f.name}`.",
                "sample": f.enum_values[0] if f.enum_values else _SAMPLE[f.kind],
            }
        )
    return {
        "name": name,
        "cmd": ep.cmd,
        "signature": _signature(fields),
        "groups": _groups(fields, http),
        "raw_body": next((f["arg"] for f in fields if f["location"] == "body"), None),
        "path_expr": _path_expr(rest, fields) if http else None,
        "has_path_params": any(f["location"] == "path" for f in fields),
        "title": _human(name),
        "description": (
            f"Asks the device ({ep.cmd}) and returns its reply."
            if is_query
            else f"Sends {ep.cmd} to the device."
        ),
        "http_method": verb if http else None,
        "path": rest if http else None,
        "operation": rest if ep.transport == TransportType.GRAPHQL else None,
        "document": ep.document,
        "fields": fields,
        "sample_data": {f["arg"]: f["sample"] for f in fields if f["required"]},
        "response": is_query,
        "domain": domain,
    }


def _signature(fields: list[dict[str, Any]]) -> list[str]:
    """Keyword-only parameters, one per line: required first, then optional."""
    required = [f"{f['arg']}: {f['py_type']}," for f in fields if f["required"]]
    optional = [f"{f['arg']}: {f['py_type']} | None = None," for f in fields if not f["required"]]
    return ["*,", *required, *optional] if fields else []


def _groups(fields: list[dict[str, Any]], http: bool) -> list[dict[str, Any]]:
    """Dicts the SDK method builds: JSON body, query string or form (HTTP); else one."""
    if not http:  # GraphQL variables / WebSocket frame: always a (maybe empty) dict
        spec: list[tuple[str, str, list[dict[str, Any]]]] = [("params", "params", fields)]
    else:
        raw = any(f["location"] == "body" for f in fields)  # an opaque whole-body argument
        spec = [
            (var, kwarg, members)
            for var, kwarg, location in (
                ("body", "body", "json"),
                ("query", "params", "query"),
                ("form", "data", "form"),
            )
            if (members := [f for f in fields if f["location"] == location])
            and not (raw and location == "json")
        ]
    return [
        {
            "var": var,
            "kwarg": kwarg,
            "required": [f for f in members if f["required"]],
            "optional": [f for f in members if not f["required"]],
        }
        for var, kwarg, members in spec
    ]


def _path_expr(path: str, fields: list[dict[str, Any]]) -> str:
    """Python expression for the request path: "/home/{axis}" → f"/home/{quote(...)}"."""
    args: dict[str, str] = {f["wire"]: f["arg"] for f in fields if f["location"] == "path"}
    if not args:
        return repr(path).replace("'", '"')

    def sub(m: re.Match[str]) -> str:
        return "{quote(str(" + args.get(m.group(1), _snake(m.group(1))) + '), safe="")}'

    return 'f"' + _PATH_PARAM.sub(sub, path) + '"'


def services_yaml(actions: list[dict[str, Any]], domain: str) -> dict[str, Any]:
    """services.yaml content: fields and selectors (names live in strings.json)."""
    out: dict[str, Any] = {}
    for a in actions:
        fields: dict[str, Any] = {
            "config_entry_id": {
                "required": True,
                "selector": {"config_entry": {"integration": domain}},
            }
        }
        for f in a["fields"]:
            fields[f["arg"]] = {"required": f["required"], "selector": f["selector"]}
        out[a["name"]] = {"fields": fields}
    return out


def strings(actions: list[dict[str, Any]], device_name: str) -> dict[str, Any]:
    """The "services" and "exceptions" sections of strings.json."""
    if not actions:
        return {}
    services: dict[str, Any] = {}
    for a in actions:
        fields = {
            "config_entry_id": {
                "name": "Device",
                "description": f"The {device_name} to send the action to.",
            }
        }
        for f in a["fields"]:
            fields[f["arg"]] = {"name": f["name"], "description": f["description"]}
        services[a["name"]] = {
            "name": a["title"],
            "description": a["description"],
            "fields": fields,
        }
    return {
        "services": services,
        "exceptions": {
            "entry_not_found": {"message": f"No {device_name} with this config entry ID."},
            "entry_not_loaded": {"message": f"{device_name} is not loaded."},
            "action_failed": {"message": "{action} failed: {error}"},
        },
    }
