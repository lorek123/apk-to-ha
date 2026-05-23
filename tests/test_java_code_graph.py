# SPDX-License-Identifier: MIT
"""Tests for JavaCodeGraph tree-sitter call graph builder."""
from __future__ import annotations

from pathlib import Path

import pytest

from engine.extraction.java_code_graph import JavaCodeGraph


def _write(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


_SIGNER_JAVA = """\
package com.example.auth;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Signer {
    private String sign(String timestamp, String path) {
        String msg = buildMessage(timestamp, path);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(this.apiKey.getBytes(), "HmacSHA256"));
        return Base64.encode(mac.doFinal(msg.getBytes()));
    }

    private String buildMessage(String ts, String path) {
        return ts + "\\n" + path;
    }
}
"""

_HELPER_JAVA = """\
package com.example.auth;

public class AuthHelper {
    public static String makeNonce() {
        return Long.toString(System.currentTimeMillis());
    }
}
"""


# ── build ─────────────────────────────────────────────────────────────────────

def test_build_indexes_methods(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    assert any("sign" in k for k in g.method_sources)
    assert any("buildMessage" in k for k in g.method_sources)


def test_build_empty_dir(tmp_path: Path) -> None:
    g = JavaCodeGraph.build(tmp_path)
    assert g.method_sources == {}


def test_build_multiple_files(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    _write(tmp_path, "com/example/auth/AuthHelper.java", _HELPER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    assert any("makeNonce" in k for k in g.method_sources)
    assert any("sign" in k for k in g.method_sources)


def test_build_class_name_in_key(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    # Keys should be ClassName.methodName
    assert any(k.startswith("Signer.") for k in g.method_sources)


# ── method_sources ────────────────────────────────────────────────────────────

def test_method_source_contains_body(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    src = g.get_method_source("buildMessage")
    assert src is not None
    assert "return ts" in src


def test_method_source_returns_none_for_missing(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    assert g.get_method_source("nonExistentMethod") is None


def test_method_source_exact_key(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    src = g.get_method_source("Signer.sign")
    assert src is not None
    assert "doFinal" in src


# ── call graph edges ──────────────────────────────────────────────────────────

def test_callees_recorded(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    sign_key = next(k for k in g.method_sources if k.endswith(".sign"))
    callees = g.method_callees.get(sign_key, [])
    assert "buildMessage" in callees


def test_callers_recorded(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    callers = g.callers_of("buildMessage")
    assert any("sign" in c for c in callers)


def test_callers_of_missing_returns_empty(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    assert g.callers_of("neverCalledMethod") == []


# ── bfs_from ──────────────────────────────────────────────────────────────────

def test_bfs_from_short_name(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    reachable = g.bfs_from("sign")
    names = [k.split(".")[-1] for k in reachable]
    assert "sign" in names
    assert "buildMessage" in names


def test_bfs_from_max_hops_zero(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    reachable = g.bfs_from("sign", max_hops=0)
    assert len(reachable) == 1
    assert reachable[0].endswith(".sign")


def test_bfs_from_missing_returns_empty(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    assert g.bfs_from("ghostMethod") == []


def test_bfs_cross_file(tmp_path: Path) -> None:
    """BFS follows calls across files."""
    caller = """\
package com.example;
public class A {
    public String doWork() {
        return helper();
    }
}
"""
    callee = """\
package com.example;
public class B {
    public static String helper() {
        return "done";
    }
}
"""
    _write(tmp_path, "com/example/A.java", caller)
    _write(tmp_path, "com/example/B.java", callee)
    g = JavaCodeGraph.build(tmp_path)
    reachable = g.bfs_from("doWork")
    names = [k.split(".")[-1] for k in reachable]
    assert "doWork" in names
    assert "helper" in names


# ── subgraph_text ─────────────────────────────────────────────────────────────

def test_subgraph_text_includes_method_bodies(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    text = g.subgraph_text("sign", max_hops=2)
    assert "doFinal" in text or "buildMessage" in text


def test_subgraph_text_missing_start_returns_empty(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _SIGNER_JAVA)
    g = JavaCodeGraph.build(tmp_path)
    assert g.subgraph_text("ghostMethod") == ""


# ── integration: signing_tracer uses graph ────────────────────────────────────

def test_tracer_uses_graph_for_cross_method(tmp_path: Path) -> None:
    """Graph enables the tracer to resolve a helper in a *separate* file."""
    auth_java = """\
package com.example.auth;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class ApiSigner {
    public String sign(String apiKey) {
        String payload = PayloadBuilder.build();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(apiKey.getBytes(), "HmacSHA256"));
        return Base64.encode(mac.doFinal(payload.getBytes()));
    }
}
"""
    builder_java = """\
package com.example.auth;
public class PayloadBuilder {
    public static String build() {
        String ts = String.valueOf(System.currentTimeMillis());
        String path = "/api/v1/data";
        return ts + path;
    }
}
"""
    _write(tmp_path, "com/example/auth/ApiSigner.java", auth_java)
    _write(tmp_path, "com/example/auth/PayloadBuilder.java", builder_java)

    from engine.extraction.crypto_scanner import CryptoUsage
    from engine.extraction.signing_tracer import trace

    usages = [CryptoUsage(
        algorithm="HMAC-SHA256",
        call_site="com.example.auth.ApiSigner",
        context_snippet='Mac.getInstance("HmacSHA256")',
        confidence=1.0,
    )]
    graph = JavaCodeGraph.build(tmp_path)
    result = trace(usages, tmp_path, graph)
    assert len(result) == 1
    # With graph, the tracer should find timestamp/path from PayloadBuilder.build()
    # or at minimum produce a non-empty trace
    assert len(result[0].components) > 0
