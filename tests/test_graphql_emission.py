# SPDX-License-Identifier: MIT
"""Tests for GraphQL emission: rendered client, config flow and tests."""

from __future__ import annotations

import py_compile
import subprocess
from pathlib import Path
from typing import Any

from engine.emitters import context as ctx_mod
from engine.emitters import hacs_emitter, sdk_emitter
from engine.ir.models import (
    AuthScheme,
    AuthType,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    EntityHint,
    FieldDef,
    FieldKind,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)

_METRICS = "query GetMetrics { metrics { cpu { percentTotal } } }"


def _op(cmd: str, document: str, *fields: FieldDef) -> Endpoint:
    return Endpoint(
        cmd=cmd,
        transport=TransportType.GRAPHQL,
        direction=Direction.TO_DEVICE,
        awaits_response=True,
        entity_hint=EntityHint.BUTTON,
        request_fields=list(fields),
        document=document,
    )


def _ctx() -> dict[str, Any]:
    ir = ProtocolIR(
        apk_path="a.apk",
        package_name="com.example.nas",
        app_name="NAS",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.GRAPHQL),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(
            type=AuthType.API_KEY, fields=[FieldDef(name="x-api-key", kind=FieldKind.STRING)]
        ),
        state=StateSchema(
            poll_endpoints=["QUERY GetMetrics"],
            fields=[
                FieldDef(
                    name="metrics_cpu_percent_total",
                    serialized_name="metrics.cpu.percentTotal",
                    kind=FieldKind.NUMBER,
                    entity_hint=EntityHint.SENSOR,
                )
            ],
        ),
        commands=[
            _op("QUERY GetMetrics", _METRICS),
            _op("MUTATION StartArray", "mutation StartArray { array { start } }"),
            _op("MUTATION StopArray", "mutation StopArray { array { stop } }"),
            _op(
                "MUTATION StartContainer",
                "mutation StartContainer($id: ID!) { docker { start(id: $id) } }",
                FieldDef(name="id", kind=FieldKind.STRING, required=True),
            ),
        ],
        extra={"graphql_path": "/graphql"},
    )
    return ctx_mod.build(ir)


def test_graphql_context() -> None:
    ctx = _ctx()

    assert {b["key"]: b["maintenance"] for b in ctx["buttons"]} == {
        "start_array": False,
        "stop_array": True,  # takes everything on the array down
    }
    assert ctx["api_key_header"] == "x-api-key"
    assert ctx["poll_queries"] == [{"name": "GetMetrics", "document": _METRICS}]
    # the polled query feeds the state; StartContainer(id) needs a value: an action
    assert {u["cmd"] for u in ctx["unmapped_commands"]} == {"QUERY GetMetrics"}
    assert [(a["name"], a["operation"]) for a in ctx["actions"]] == [
        ("start_container", "StartContainer")
    ]


def test_graphql_templates_render_compile_and_lint(tmp_path: Path) -> None:
    ctx = _ctx()
    sdk_dir = sdk_emitter.emit(ctx, tmp_path)
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)
    tests_dir = hacs_emitter.emit_tests(ctx, tmp_path)
    assert tests_dir is not None

    client = (sdk_dir / "client.py").read_text()
    assert 'API_KEY_HEADER = "x-api-key"' in client
    assert '"operationName": name' in client
    assert "update_interval=POLL_INTERVAL" in (hacs_dir / "coordinator.py").read_text()
    flow = (hacs_dir / "config_flow.py").read_text()
    assert "TextSelectorType.PASSWORD" in flow  # the key isn't shown while typed
    assert "async_step_reauth_confirm" in flow
    assert "_get(data," in (sdk_dir / "models.py").read_text()  # dotted GraphQL paths

    for py in [*sdk_dir.glob("*.py"), *hacs_dir.glob("*.py"), *tests_dir.glob("*.py")]:
        py_compile.compile(str(py), doraise=True)
    ruff = subprocess.run(
        ["ruff", "check", "--select", "E,F,W,I", "--ignore", "E501", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ruff.returncode == 0, ruff.stdout
