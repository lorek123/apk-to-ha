# SPDX-License-Identifier: MIT
"""Tests for the Ktor scanner (shapes from the F-Droid Inkcast app)."""
# ruff: noqa: E501 — the Java fixtures reproduce decompiler output line for line

from __future__ import annotations

from pathlib import Path

from engine.extraction.ktor_scanner import scan
from engine.ir.models import FieldKind

_SOURCE = """package com.example.ink;
public final class DeviceSource {
    public final Object getStatus(String str) {
        String str3 = str + "/api/status";
        HttpRequestBuilder httpRequestBuilder = new HttpRequestBuilder();
        HttpRequestKt.url(httpRequestBuilder, str3);
        httpRequestBuilder.setMethod(HttpMethod.INSTANCE.getGet());
        TypeInfo t = TypeInfoJvmKt.typeInfoImpl(Reflection.typeOf(DeviceStatus.class), Reflection.getOrCreateKotlinClass(DeviceStatus.class));
    }
    public final Object listFiles(String str, String path) {
        HttpRequestBuilder httpRequestBuilder = new HttpRequestBuilder();
        HttpRequestKt.url(httpRequestBuilder, str + "/api/files");
        UtilsKt.parameter(httpRequestBuilder, "path", path);
        httpRequestBuilder.setMethod(HttpMethod.INSTANCE.getGet());
    }
    public final Object updateSettings(String str, String json) {
        String str2 = str + "/api/settings";
        HttpRequestBuilder httpRequestBuilder = new HttpRequestBuilder();
        httpRequestBuilder.setMethod(HttpMethod.INSTANCE.getPost());
        HttpRequestKt.url(httpRequestBuilder, str2);
        httpRequestBuilder.setBody(json);
    }
    public final Object getSettings(String str) {
        HttpRequestBuilder httpRequestBuilder = new HttpRequestBuilder();
        HttpRequestKt.url(httpRequestBuilder, "http://" + str + "/api/settings");
        httpRequestBuilder.setMethod(HttpMethod.INSTANCE.getGet());
    }
    public final Object delete(String str, String path) {
        ParametersBuilder parametersBuilder = ParametersKt.ParametersBuilder$default(0, 1, null);
        parametersBuilder.append("path", path);
        parametersBuilder.append("type", "file");
        Object r = FormBuildersKt.submitForm$default(this.client, str + "/delete", parametersBuilder.build(), false, null, this, 12, null);
    }
    public final Object rename(String str, final String name) {
        Parameters parameters = HttpUrlEncodedKt.parameters(new Function1() { // from class: com.example.ink.DeviceSource$$ExternalSyntheticLambda3
            public final Object invoke(Object obj) {
                return DeviceSource.rename$lambda$0(name, (ParametersBuilder) obj);
            }
        });
        Object r = FormBuildersKt.submitForm$default(httpClient, str + "/rename", parameters, false, null, this, 12, null);
    }
    static final Unit rename$lambda$0(String str, ParametersBuilder parameters) {
        parameters.append("name", str);
        return Unit.INSTANCE;
    }
}
"""

_STATUS = """package com.example.ink;
public final class DeviceStatus {
    private final long freeHeap;
    private final String ip;
    private final Integer rssi;
    private final List<String> tags;
    public DeviceStatus(long freeHeap, String ip, Integer rssi, List<String> tags) {}
}
"""


def _apk(tmp_path: Path) -> Path:
    pkg = tmp_path / "sources" / "com" / "example" / "ink"
    pkg.mkdir(parents=True)
    (pkg / "DeviceSource.java").write_text(_SOURCE)
    (pkg / "DeviceStatus.java").write_text(_STATUS)
    return tmp_path


def test_builder_requests_with_method_params_and_response(tmp_path: Path) -> None:
    eps = {e.cmd: e for e in scan(_apk(tmp_path), "com.example.ink")}

    assert set(eps) == {
        "GET /api/status",
        "GET /api/files",
        "POST /api/settings",
        "GET /api/settings",
        "POST /delete",
        "POST /rename",
    }
    status = eps["GET /api/status"]
    assert [(f.name, f.kind, f.nullable) for f in status.response_fields] == [
        ("freeHeap", FieldKind.INTEGER, False),
        ("ip", FieldKind.STRING, False),
        ("rssi", FieldKind.INTEGER, True),
    ]  # the list property is not a scalar
    assert [f.name for f in eps["GET /api/files"].request_fields] == ["path"]


def test_method_set_before_url_stays_with_its_request(tmp_path: Path) -> None:
    """setMethod(POST) before url() belongs to that request; its body must not leak
    into the next request (same builder variable name)."""
    eps = {e.cmd: e for e in scan(_apk(tmp_path), "com.example.ink")}

    body = eps["POST /api/settings"].request_fields
    assert [(f.name, f.required) for f in body] == [("body", True)]
    assert eps["GET /api/settings"].request_fields == []


def test_form_post_fields(tmp_path: Path) -> None:
    eps = {e.cmd: e for e in scan(_apk(tmp_path), "com.example.ink")}

    assert [f.name for f in eps["POST /delete"].request_fields] == ["path", "type"]  # inline
    assert [f.name for f in eps["POST /rename"].request_fields] == ["name"]  # lambda


def test_no_sources(tmp_path: Path) -> None:
    assert scan(tmp_path, "com.example.ink") == []
