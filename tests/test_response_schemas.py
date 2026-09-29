# SPDX-License-Identifier: MIT
"""Tests for linking commands to the reply classes the app decodes them into."""

from __future__ import annotations

from pathlib import Path

from engine.emitters.context import _auth_result_field
from engine.extraction.payload_resolver import PayloadResolver, top_level_body
from engine.extraction.protocol_scanner import ProtocolScanner

_API = """package com.example.device;
public class DeviceApi {
    public static final String HELLO = "hello";
    public static final String LIST = "list_things";

    public Request hello(String uuid) {
        JSONObject o = new JSONObject();
        o.put("cmd", HELLO);
        o.put("uuid", uuid);
        return createRequest(o);
    }

    public Request listThings() {
        JSONObject o = new JSONObject();
        o.put("cmd", LIST);
        return createRequest(o);
    }
}
"""

_BASE = """package com.example.device;
public class BaseResponse {
    @SerializedName("cmd")
    public String cmd;
    @SerializedName("resultCode")
    public int resultCode;
}
"""

_LIST = """package com.example.device;
public class ListResponse extends BaseResponse {
    @SerializedName("things")
    private ArrayList<Thing> things;

    public class Thing {
        @SerializedName("thing_id")
        private String id;
    }
}
"""

_SCREEN = """package com.example.device;
public class Screen {
    void load() {
        Request r = this.api.listThings();
        r.execute(new Callback() {
            public void onSuccess(String response) {
                ListResponse lr = (ListResponse) Handler.convertTypeFromResponse(
                    this, response, ListResponse.class);
            }
        });
        Request h = this.api.hello(uuid);
        h.execute(new Callback() {
            public void onSuccess(String response) {
                BaseResponse br = gson.fromJson(response, BaseResponse.class);
            }
        });
    }
}
"""


def _app(tmp_path: Path) -> Path:
    pkg = tmp_path / "sources" / "com" / "example" / "device"
    pkg.mkdir(parents=True)
    for name, src in {
        "DeviceApi": _API,
        "BaseResponse": _BASE,
        "ListResponse": _LIST,
        "Screen": _SCREEN,
    }.items():
        (pkg / f"{name}.java").write_text(src)
    return tmp_path


def test_top_level_body_skips_nested_classes() -> None:
    body = top_level_body(_LIST, "ListResponse")

    assert '"things"' in body
    assert "thing_id" not in body


def test_resolver_follows_extends_without_flattening_nested(tmp_path: Path) -> None:
    fields = PayloadResolver(_app(tmp_path)).resolve("ListResponse").fields

    assert [f.serialized_name for f in fields] == ["things", "cmd", "resultCode"]


def test_commands_get_response_schema_from_callback(tmp_path: Path) -> None:
    commands = ProtocolScanner(_app(tmp_path)).scan("com.example.device")[4]
    replies = {c.cmd: [f.serialized_name for f in c.response_fields] for c in commands}

    # Envelope framing (cmd) is dropped; the status code and payload stay.
    assert replies["list_things"] == ["things", "resultCode"]
    assert replies["hello"] == ["resultCode"]


def test_auth_result_field_from_handshake_reply(tmp_path: Path) -> None:
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

    commands = ProtocolScanner(_app(tmp_path)).scan("com.example.device")[4]
    ir = ProtocolIR(
        apk_path="app.apk",
        package_name="com.example.device",
        app_name="Device",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.HANDSHAKE, handshake_cmd="hello"),
        state=StateSchema(),
        commands=commands,
    )

    assert _auth_result_field(ir) == "resultCode"
    assert _auth_result_field(ir.model_copy(update={"commands": []})) is None
