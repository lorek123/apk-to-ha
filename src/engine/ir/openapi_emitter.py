# SPDX-License-Identifier: MIT
"""P3-2 — Translate ProtocolIR → OpenAPI 3.0.3 document (dict, ready for YAML dump).

Type inference rules:
  FieldKind.STRING   → {type: string}
  FieldKind.INTEGER  → {type: integer}
  FieldKind.NUMBER   → {type: number}
  FieldKind.BOOLEAN  → {type: boolean}
  FieldKind.ENUM     → {type: string, enum: [...]}
  FieldKind.OBJECT   → {type: object}
  FieldKind.ARRAY    → {type: array, items: {type: string}}

nullable fields get nullable: true.
required: false fields are omitted from the `required` list.
Repeated payload shapes are extracted as $ref components.
"""
from __future__ import annotations

from typing import Any

from .models import Direction, Endpoint, FieldDef, FieldKind, ProtocolIR, TransportType


def emit(ir: ProtocolIR) -> dict[str, Any]:
    """Return a dict representing the OpenAPI 3.0.3 document for *ir*."""
    schemas: dict[str, Any] = {}

    paths: dict[str, Any] = {}
    for ep in ir.commands + ir.events:
        _add_path(ep, paths, schemas, ir)

    doc: dict[str, Any] = {
        "openapi": "3.0.3",
        "info": {
            "title": f"{ir.app_name} Device API",
            "version": ir.version_name or "1.0.0",
            "description": (
                f"Auto-generated from APK `{ir.package_name}` "
                f"by HACS Integration Engine."
            ),
        },
        "servers": _servers(ir),
        "paths": paths,
    }

    if schemas:
        doc["components"] = {"schemas": schemas}

    return doc


# ── path builder ──────────────────────────────────────────────────────────────

def _add_path(
    ep: Endpoint,
    paths: dict[str, Any],
    schemas: dict[str, Any],
    ir: ProtocolIR,
) -> None:
    path_key = f"/{ep.cmd}"
    method = "post" if ep.direction == Direction.TO_DEVICE else "get"

    operation: dict[str, Any] = {
        "summary": ep.description or ep.cmd,
        "operationId": ep.cmd,
        "tags": [_tag(ir.transport.type, ep.direction)],
    }

    if ep.request_fields:
        schema_name = _schema_name(ep.cmd, "Request")
        schemas[schema_name] = _fields_to_schema(ep.request_fields)
        operation["requestBody"] = {
            "required": True,
            "content": {
                _media_type(ir.transport.type): {
                    "schema": {"$ref": f"#/components/schemas/{schema_name}"},
                },
            },
        }

    responses: dict[str, Any] = {}
    if ep.response_fields:
        schema_name = _schema_name(ep.cmd, "Response")
        schemas[schema_name] = _fields_to_schema(ep.response_fields)
        responses["200"] = {
            "description": "Success",
            "content": {
                _media_type(ir.transport.type): {
                    "schema": {"$ref": f"#/components/schemas/{schema_name}"},
                },
            },
        }
    else:
        responses["200"] = {"description": "Success"}

    if ep.confidence < 0.7:
        responses["200"]["description"] += f" (confidence={ep.confidence:.2f})"

    operation["responses"] = responses

    if path_key not in paths:
        paths[path_key] = {}
    paths[path_key][method] = operation


# ── field → JSON Schema ───────────────────────────────────────────────────────

def _fields_to_schema(fields: list[FieldDef]) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []

    for f in fields:
        key = f.serialized_name or f.name
        prop = _field_schema(f)
        if f.nullable:
            prop["nullable"] = True
        if f.description:
            prop["description"] = f.description
        properties[key] = prop
        if f.required:
            required.append(key)

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


_KIND_TO_OPENAPI: dict[FieldKind, dict[str, Any]] = {
    FieldKind.STRING:  {"type": "string"},
    FieldKind.INTEGER: {"type": "integer"},
    FieldKind.NUMBER:  {"type": "number"},
    FieldKind.BOOLEAN: {"type": "boolean"},
    FieldKind.OBJECT:  {"type": "object"},
    FieldKind.ARRAY:   {"type": "array", "items": {"type": "string"}},
}


def _field_schema(f: FieldDef) -> dict[str, Any]:
    if f.kind == FieldKind.ENUM and f.enum_values:
        return {"type": "string", "enum": list(f.enum_values)}
    return dict(_KIND_TO_OPENAPI.get(f.kind, {"type": "string"}))


# ── helpers ───────────────────────────────────────────────────────────────────

def _schema_name(cmd: str, suffix: str) -> str:
    """'powerControl' + 'Request' → 'PowerControlRequest'"""
    return cmd[0].upper() + cmd[1:] + suffix


def _tag(transport: TransportType, direction: Direction) -> str:
    tmap = {
        TransportType.WEBSOCKET: "websocket",
        TransportType.HTTP_REST: "http",
        TransportType.TCP_SOCKET: "tcp",
        TransportType.UDP: "udp",
        TransportType.BLE: "ble",
    }
    prefix = tmap.get(transport, "unknown")
    suffix = "commands" if direction == Direction.TO_DEVICE else "events"
    return f"{prefix}-{suffix}"


def _media_type(transport: TransportType) -> str:
    if transport == TransportType.HTTP_REST:
        return "application/json"
    return "application/json"  # WS/TCP frames are also JSON in practice


def _servers(ir: ProtocolIR) -> list[dict[str, Any]]:
    port = ir.transport.port
    ttype = ir.transport.type
    if ttype == TransportType.WEBSOCKET:
        scheme = "wss" if ir.transport.tls else "ws"
        url = f"{scheme}://{{host}}:{port or 8887}"
    elif ttype == TransportType.HTTP_REST:
        scheme = "https" if ir.transport.tls else "http"
        url = f"{scheme}://{{host}}:{port or 80}"
    else:
        url = f"tcp://{{host}}:{port or 0}"

    return [{
        "url": url,
        "variables": {"host": {"default": "192.168.1.1", "description": "Device IP address"}},
    }]
