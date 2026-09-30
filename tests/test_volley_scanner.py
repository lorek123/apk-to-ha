# SPDX-License-Identifier: MIT
"""Tests for the Volley HTTP scanner (patterns from the F-Droid Home App)."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.extraction.volley_scanner import scan, split_args, url_template
from engine.ir.models import (
    AuthScheme,
    AuthType,
    DiscoveryMechanism,
    DiscoveryType,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)
from engine.pipeline import _emit_blocker


@pytest.mark.parametrize(
    ("expr", "expected"),
    [
        ('this.url + "api/" + getUsername() + "/groups"', "/api/{username}/groups"),
        ('addressPrefix + "/lights/" + id', "/lights/{id}"),
        ('this.url + "relay/" + str + "?turn=" + (z ? "on" : "off")', "/relay/{str}"),
        (
            'Foo$$ExternalSyntheticOutline0.m137m(str, "rpc/Shelly.GetConfig")',
            "/rpc/Shelly.GetConfig",
        ),
        ('"http://127.0.0.1/api/config"', "/api/config"),
        ("this.url + obj", None),  # no fixed segment
        ('base + "/" + id', None),
    ],
)
def test_url_template(expr: str, expected: str | None) -> None:
    assert url_template(expr) == expected


def test_split_args_respects_nesting_and_strings() -> None:
    src = 'new JsonObjectRequest(0, f(a, b) + "x,y", null, new L(this, cb), e);'

    assert split_args(src, src.index("(") + 1) == [
        "0",
        'f(a, b) + "x,y"',
        "null",
        "new L(this, cb)",
        "e",
    ]


_API = """package com.example.home;
public final class LampAPI {
    public void setOn(boolean z) {
        String str2 = this.url + "relay/" + this.channel + "?turn=" + (z ? "on" : "off");
        this.queue.add(new JsonObjectRequest(0, str2, null, ok, err));
    }
    public void info(int i2) {
        this.queue.add(new JsonObjectRequest(i2, this.url + "status", null, ok, err));
        this.queue.add(new JsonObjectRequest(0, this.url + "status", null, ok, err));
    }
    public void settings() {
        this.queue.add(new AuthRequest(this.url + "settings", this.secrets, ok, err));
    }
}
"""

_AUTH_REQUEST = """package com.example.home;
public final class AuthRequest extends JsonObjectRequest { }
"""


def test_scan_resolves_locals_subclasses_and_methods(tmp_path: Path) -> None:
    pkg = tmp_path / "sources" / "com" / "example" / "home"
    pkg.mkdir(parents=True)
    (pkg / "LampAPI.java").write_text(_API)
    (pkg / "AuthRequest.java").write_text(_AUTH_REQUEST)

    cmds = sorted(e.cmd for e in scan(tmp_path, "com.example.home"))

    # local var resolved; app subclass with URL-first ctor; REQUEST dropped where GET known
    assert cmds == ["GET /relay/{channel}", "GET /status", "REQUEST /settings"]


def _ir(transport: TransportType, auth: AuthType = AuthType.NONE, cmds: bool = True) -> ProtocolIR:
    from engine.ir.models import Direction, Endpoint

    commands = (
        [Endpoint(cmd="x", transport=transport, direction=Direction.TO_DEVICE)] if cmds else []
    )
    return ProtocolIR(
        apk_path="a.apk",
        package_name="com.example",
        app_name="X",
        framework=Framework.NATIVE,
        transport=TransportContract(type=transport),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=auth),
        state=StateSchema(),
        commands=commands,
    )


def _blocked(ir: ProtocolIR) -> str | None:
    blocker = _emit_blocker(ir)
    return blocker[0] if blocker else None


def test_emit_blocker() -> None:
    assert _blocked(_ir(TransportType.WEBSOCKET)) is None
    assert _blocked(_ir(TransportType.BLE)) is None
    assert _blocked(_ir(TransportType.WEBSOCKET, cmds=False)) == "nothing-extracted"
    assert _blocked(_ir(TransportType.BLE, AuthType.CHALLENGE_RESPONSE)) == "unsupported-auth"
    assert _blocked(_ir(TransportType.HTTP_REST)) == "unsupported-transport"


def test_url_template_scheme_and_host_are_the_base() -> None:
    assert url_template('"http://" + ((String) str) + "/api/status"') == "/api/status"
    assert url_template('"http://" + host + ":" + port + "/x"') is not None
