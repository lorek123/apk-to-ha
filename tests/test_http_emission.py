# SPDX-License-Identifier: MIT
"""Tests for HTTP (poll-based) emission: context rules and rendered code."""

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


def _cmd(cmd: str, hint: EntityHint, *fields: tuple[str, FieldKind]) -> Endpoint:
    return Endpoint(
        cmd=cmd,
        transport=TransportType.HTTP_REST,
        direction=Direction.TO_DEVICE,
        awaits_response=True,
        entity_hint=hint,
        request_fields=[FieldDef(name=n, kind=k) for n, k in fields],
    )


def _ctx() -> dict[str, Any]:
    ir = ProtocolIR(
        apk_path="a.apk",
        package_name="com.example.scope",
        app_name="Scope",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.HTTP_REST, port=8080),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(
            poll_endpoint="GET /status",
            fields=[FieldDef(name="temp_c", kind=FieldKind.NUMBER, entity_hint=EntityHint.SENSOR)],
        ),
        commands=[
            _cmd("GET /status", EntityHint.BUTTON),
            _cmd("POST /stop", EntityHint.BUTTON),
            _cmd("POST /shutdown", EntityHint.BUTTON),
            _cmd("POST /home/{axis}", EntityHint.BUTTON),
            _cmd("POST /adc_rate", EntityHint.NUMBER, ("hz", FieldKind.INTEGER)),
            _cmd(
                "POST /goto/radec",
                EntityHint.NUMBER,
                ("ra", FieldKind.NUMBER),
                ("dec", FieldKind.NUMBER),
            ),
        ],
    )
    return ctx_mod.build(ir)


def test_http_keys_path_params_and_queries() -> None:
    ctx = _ctx()

    assert [(b["key"], b["path"], b["maintenance"]) for b in ctx["buttons"]] == [
        ("stop", "/stop", False),
        ("shutdown", "/shutdown", True),
    ]
    assert [(n["key"], n["param"], n["param_kind"]) for n in ctx["numbers"]] == [
        ("adc_rate", "hz", "integer")
    ]
    unmapped = {u["cmd"] for u in ctx["unmapped_commands"]}
    # a GET is a query; /home/{axis} needs an axis; goto needs two values
    assert unmapped == {"GET /status", "POST /home/{axis}", "POST /goto/radec"}
    assert (ctx["poll_method"], ctx["poll_path"]) == ("GET", "/status")


def test_http_templates_render_compile_and_lint(tmp_path: Path) -> None:
    ctx = _ctx()
    sdk_dir = sdk_emitter.emit(ctx, tmp_path)
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)
    tests_dir = hacs_emitter.emit_tests(ctx, tmp_path)
    assert tests_dir is not None

    client = (sdk_dir / "client.py").read_text()
    assert 'self._request("GET", "/status")' in client
    assert '"/adc_rate"' in client
    assert '{"hz": int(value)}' in client  # integer param sent as int
    assert "update_interval=POLL_INTERVAL" in (hacs_dir / "coordinator.py").read_text()
    assert "await client.get_state()" in (hacs_dir / "config_flow.py").read_text()
    assert "async_fire_time_changed" in (tests_dir / "test_integration.py").read_text()

    for py in [*sdk_dir.glob("*.py"), *hacs_dir.glob("*.py"), *tests_dir.glob("*.py")]:
        py_compile.compile(str(py), doraise=True)
    ruff = subprocess.run(
        ["ruff", "check", "--select", "E,F,W,I", "--ignore", "E501", str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ruff.returncode == 0, ruff.stdout
