# SPDX-License-Identifier: MIT
"""Tests for P3-2 OpenAPI emitter and P3-3 validator."""
from __future__ import annotations

import pytest

from engine.ir.models import (
    AuthScheme,
    AuthType,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    FieldDef,
    FieldKind,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)
from engine.ir.openapi_emitter import (
    _field_schema,
    _fields_to_schema,
    _schema_name,
    emit,
)
from engine.ir.openapi_validator import validate


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_ir(**overrides) -> ProtocolIR:
    defaults = dict(
        apk_path="/tmp/test.apk",
        package_name="com.example.device",
        app_name="My Device",
        version_name="1.2.3",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887),
        discovery=DiscoveryMechanism(type=DiscoveryType.UDP_BROADCAST, port=12345),
        auth=AuthScheme(type=AuthType.HANDSHAKE, handshake_cmd="grantAccess"),
        state=StateSchema(push_cmd="gin"),
        commands=[
            Endpoint(
                cmd="powerControl",
                transport=TransportType.WEBSOCKET,
                direction=Direction.TO_DEVICE,
                request_fields=[
                    FieldDef(name="enable", kind=FieldKind.BOOLEAN),
                    FieldDef(name="brightness", kind=FieldKind.INTEGER, required=False),
                ],
                response_fields=[
                    FieldDef(name="result", kind=FieldKind.STRING),
                ],
            ),
        ],
        events=[
            Endpoint(
                cmd="stateUpdate",
                transport=TransportType.WEBSOCKET,
                direction=Direction.FROM_DEVICE,
                response_fields=[
                    FieldDef(name="power", kind=FieldKind.BOOLEAN),
                    FieldDef(name="temperature", kind=FieldKind.NUMBER, nullable=True),
                ],
            ),
        ],
    )
    defaults.update(overrides)
    return ProtocolIR(**defaults)


# ── unit: _field_schema ───────────────────────────────────────────────────────

@pytest.mark.parametrize("kind,expected_type", [
    (FieldKind.STRING, "string"),
    (FieldKind.INTEGER, "integer"),
    (FieldKind.NUMBER, "number"),
    (FieldKind.BOOLEAN, "boolean"),
    (FieldKind.OBJECT, "object"),
    (FieldKind.ARRAY, "array"),
])
def test_field_schema_type_mapping(kind, expected_type):
    f = FieldDef(name="x", kind=kind)
    assert _field_schema(f)["type"] == expected_type


def test_field_schema_enum():
    f = FieldDef(name="mode", kind=FieldKind.ENUM, enum_values=["low", "high"])
    schema = _field_schema(f)
    assert schema["type"] == "string"
    assert schema["enum"] == ["low", "high"]


def test_fields_to_schema_required():
    fields = [
        FieldDef(name="enable", kind=FieldKind.BOOLEAN, required=True),
        FieldDef(name="level", kind=FieldKind.INTEGER, required=False),
    ]
    schema = _fields_to_schema(fields)
    assert "enable" in schema["required"]
    assert "level" not in schema.get("required", [])


def test_fields_to_schema_nullable():
    fields = [FieldDef(name="temp", kind=FieldKind.NUMBER, nullable=True)]
    schema = _fields_to_schema(fields)
    assert schema["properties"]["temp"]["nullable"] is True


def test_fields_to_schema_serialized_name():
    fields = [FieldDef(name="myField", serialized_name="my_field", kind=FieldKind.STRING)]
    schema = _fields_to_schema(fields)
    assert "my_field" in schema["properties"]
    assert "myField" not in schema["properties"]


def test_schema_name():
    assert _schema_name("powerControl", "Request") == "PowerControlRequest"
    assert _schema_name("stateUpdate", "Response") == "StateUpdateResponse"


# ── unit: emit() structure ────────────────────────────────────────────────────

def test_emit_returns_dict():
    doc = emit(_make_ir())
    assert isinstance(doc, dict)


def test_emit_openapi_version():
    doc = emit(_make_ir())
    assert doc["openapi"] == "3.0.3"


def test_emit_info_fields():
    doc = emit(_make_ir())
    assert doc["info"]["title"] == "My Device Device API"
    assert doc["info"]["version"] == "1.2.3"


def test_emit_info_version_fallback():
    ir = _make_ir(version_name=None)
    doc = emit(ir)
    assert doc["info"]["version"] == "1.0.0"


def test_emit_paths_contain_commands():
    doc = emit(_make_ir())
    assert "/powerControl" in doc["paths"]


def test_emit_paths_contain_events():
    doc = emit(_make_ir())
    assert "/stateUpdate" in doc["paths"]


def test_emit_command_uses_post():
    doc = emit(_make_ir())
    assert "post" in doc["paths"]["/powerControl"]


def test_emit_event_uses_get():
    doc = emit(_make_ir())
    assert "get" in doc["paths"]["/stateUpdate"]


def test_emit_request_body_ref():
    doc = emit(_make_ir())
    body = doc["paths"]["/powerControl"]["post"]["requestBody"]
    ref = body["content"]["application/json"]["schema"]["$ref"]
    assert "PowerControlRequest" in ref


def test_emit_response_ref():
    doc = emit(_make_ir())
    resp = doc["paths"]["/powerControl"]["post"]["responses"]["200"]
    ref = resp["content"]["application/json"]["schema"]["$ref"]
    assert "PowerControlResponse" in ref


def test_emit_components_schemas_populated():
    doc = emit(_make_ir())
    schemas = doc["components"]["schemas"]
    assert "PowerControlRequest" in schemas
    assert "PowerControlResponse" in schemas
    assert "StateUpdateResponse" in schemas


def test_emit_no_request_body_for_no_fields():
    ir = _make_ir(commands=[
        Endpoint(
            cmd="ping",
            transport=TransportType.WEBSOCKET,
            direction=Direction.TO_DEVICE,
        ),
    ])
    doc = emit(ir)
    assert "requestBody" not in doc["paths"]["/ping"]["post"]


def test_emit_ws_server_url():
    doc = emit(_make_ir())
    url = doc["servers"][0]["url"]
    assert url.startswith("ws://")
    assert "8887" in url


def test_emit_http_server_url():
    ir = _make_ir(transport=TransportContract(type=TransportType.HTTP_REST, port=8080))
    doc = emit(ir)
    url = doc["servers"][0]["url"]
    assert url.startswith("http://")
    assert "8080" in url


def test_emit_tags_on_operations():
    doc = emit(_make_ir())
    tags = doc["paths"]["/powerControl"]["post"]["tags"]
    assert len(tags) > 0
    assert "websocket" in tags[0]


def test_emit_empty_ir_no_crash():
    ir = _make_ir(commands=[], events=[])
    doc = emit(ir)
    assert doc["paths"] == {}
    assert "components" not in doc


# ── P3-3 validator ────────────────────────────────────────────────────────────

def test_valid_doc_passes():
    doc = emit(_make_ir())
    report = validate(doc)
    assert report.passed
    assert report.error_count == 0


def test_invalid_doc_fails():
    report = validate({"openapi": "3.0.3", "info": {}, "paths": {}})
    assert not report.passed
    assert report.error_count > 0


def test_duplicate_operation_id_fails():
    # Craft a doc with two different paths sharing the same operationId
    doc = emit(_make_ir())
    doc["paths"]["/aliasControl"] = {
        "post": {
            "operationId": "powerControl",  # duplicate of /powerControl
            "tags": ["websocket-commands"],
            "responses": {"200": {"description": "ok"}},
        }
    }
    report = validate(doc)
    assert not report.passed
    assert any("Duplicate" in e for e in report.errors)


def test_validator_warns_missing_version():
    doc = emit(_make_ir())
    doc["info"].pop("version")
    report = validate(doc)
    assert any("version" in w for w in report.warnings)


def test_validator_round_trip_ir():
    """Full round-trip: IR → OpenAPI dict → YAML string → validate."""
    import yaml
    ir = _make_ir()
    doc = emit(ir)
    yaml_str = yaml.dump(doc, sort_keys=False)
    reloaded = yaml.safe_load(yaml_str)
    report = validate(reloaded)
    assert report.passed


# ── snapshot integration ──────────────────────────────────────────────────────

def test_snapshot_writes_openapi_yaml(tmp_path):
    from unittest.mock import patch
    import engine.snapshot.harness as harness
    with patch.object(harness, "_SNAPSHOTS_DIR", tmp_path):
        snap_dir = harness.write("test_apk", _make_ir(), tmp_path)
    assert (snap_dir / "openapi.yaml").exists()
    assert (snap_dir / "openapi_validation.json").exists()


def test_snapshot_openapi_yaml_is_valid(tmp_path):
    import json
    from unittest.mock import patch
    import engine.snapshot.harness as harness
    with patch.object(harness, "_SNAPSHOTS_DIR", tmp_path):
        snap_dir = harness.write("test_apk", _make_ir(), tmp_path)
    report_data = json.loads((snap_dir / "openapi_validation.json").read_text())
    assert report_data["passed"] is True
