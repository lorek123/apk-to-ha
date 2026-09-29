# SPDX-License-Identifier: MIT
"""Tests for the OkHttp scanner (shapes from the F-Droid radio telescope app)."""
# ruff: noqa: E501 — the Java fixtures reproduce decompiler output line for line

from __future__ import annotations

from pathlib import Path

from engine.extraction.okhttp_scanner import json_map_state, scan
from engine.extraction.protocol_scanner import ProtocolScanner
from engine.ir.models import FieldKind, TransportType

_API = """package com.example.scope;
public final class ScopeApi {
    public final Object getStatus() {
        Response r = this.client.newCall(new Request.Builder().url(this.baseUrl + "/status").get().build()).execute();
    }
    private final Object m6120postgIAlus(String path, Map<String, ? extends Object> body) {
        Request.Builder builderUrl = new Request.Builder().url(this.baseUrl + path);
        Response r = this.client.newCall(builderUrl.post(companion.create(json, this.json)).build()).execute();
    }
    static /* synthetic */ Object m6121postgIAlus$default(ScopeApi scopeApi, String str, Map map, int i, Object obj) {
        return scopeApi.m6120postgIAlus(str, map);
    }
    public final Object m6122gotoXYZ(double az, double el) {
        return m6120postgIAlus("/goto", MapsKt.mapOf(TuplesKt.m82to("az", Double.valueOf(az)), TuplesKt.m82to("el", Double.valueOf(el))));
    }
    public final Object m6123stopABC() {
        return m6121postgIAlus$default(this, "/stop", null, 2, null);
    }
}
"""

_WS = """package com.example.scope;
public final class ScopeSocket {
    public final void connect() {
        this.ws = this.client.newWebSocket(new Request.Builder().url(base + "/ws/status").build(), new WebSocketListener() {
            public void onMessage(WebSocket w, String text) {
                Map map = (Map) gson.fromJson(text, Map.class);
                Object obj = map.get("az");
                Double d = obj instanceof Double ? (Double) obj : null;
                Object obj2 = map.get("moving");
                Boolean b = obj2 instanceof Boolean ? (Boolean) obj2 : null;
                Object obj3 = map.get("temp_c");
                Double d3 = obj3 instanceof Double ? (Double) obj3 : null;
            }
        });
    }
}
"""


def _app(tmp_path: Path) -> Path:
    pkg = tmp_path / "sources" / "com" / "example" / "scope"
    pkg.mkdir(parents=True)
    (pkg / "ScopeApi.java").write_text(_API)
    (pkg / "ScopeSocket.java").write_text(_WS)
    return tmp_path


def test_direct_builders_wrappers_and_streams(tmp_path: Path) -> None:
    eps = {e.cmd: e for e in scan(_app(tmp_path), "com.example.scope")}

    assert set(eps) == {"GET /status", "POST /goto", "POST /stop", "WS /ws/status"}
    assert [(f.name, f.kind) for f in eps["POST /goto"].request_fields] == [
        ("az", FieldKind.NUMBER),
        ("el", FieldKind.NUMBER),
    ]
    assert eps["WS /ws/status"].transport is TransportType.WEBSOCKET


def test_hand_parsed_json_state(tmp_path: Path) -> None:
    fields = json_map_state(_app(tmp_path), "com.example.scope")

    assert [(f.name, f.kind) for f in fields] == [
        ("az", FieldKind.NUMBER),
        ("moving", FieldKind.BOOLEAN),
        ("temp_c", FieldKind.NUMBER),
    ]


def test_protocol_scanner_polls_status_over_http(tmp_path: Path) -> None:
    transport, _, _, state, commands, events = ProtocolScanner(_app(tmp_path)).scan(
        "com.example.scope"
    )

    # Telemetry arrives on a WebSocket, but commands are HTTP: that's the transport.
    assert transport.type is TransportType.HTTP_REST
    assert state.poll_endpoint == "GET /status"
    assert {c.cmd for c in commands} == {"GET /status", "POST /goto", "POST /stop"}
    assert [e.cmd for e in events] == ["WS /ws/status"]
