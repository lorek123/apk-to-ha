# SPDX-License-Identifier: MIT
"""Tests for P2-5 static signing-input tracer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from engine.extraction.crypto_scanner import CryptoUsage
from engine.extraction.signing_tracer import (
    LLM_THRESHOLD,
    _classify_name,
    _find_assignment,
    _is_string_literal,
    _parse_stringbuilder,
    _split_concat,
    _unwrap_bytes,
    trace,
)
from engine.ir.models import SigningTrace

# ── unit: _split_concat ───────────────────────────────────────────────────────


def test_split_concat_simple() -> None:
    assert _split_concat("a + b + c") == ["a", "b", "c"]


def test_split_concat_with_literal() -> None:
    assert _split_concat('timestamp + ":" + path') == ["timestamp", '":"', "path"]


def test_split_concat_preserves_parens() -> None:
    parts = _split_concat("(a + b) + c")
    assert "(a + b)" in parts
    assert "c" in parts


def test_split_concat_nested_call() -> None:
    # String.valueOf(x) should not be split inside the call
    parts = _split_concat('String.valueOf(ts) + "\\n" + path')
    assert any("valueOf" in p for p in parts)
    assert any("path" in p for p in parts)


def test_split_concat_empty() -> None:
    assert _split_concat("") == []


def test_split_concat_no_concat() -> None:
    assert _split_concat("timestamp") == ["timestamp"]


# ── unit: _classify_name ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name,expected",
    [
        ("timestamp", "timestamp"),
        ("ts", "timestamp"),
        ("epoch", "timestamp"),
        ("nonce", "nonce"),
        ("requestPath", "path"),
        ("url", "path"),
        ("httpMethod", "http_method"),
        ("requestBody", "body"),
        ("data", "body"),
        ("apiKey", "secret_key"),
        ("secretKey", "secret_key"),
        ("hmacKey", "secret_key"),
        ("randomVar", "nonce"),
        ("var0", "unknown"),
        ("someWeirdThing", "unknown"),
    ],
)
def test_classify_name(name: Any, expected: Any) -> None:
    assert _classify_name(name) == expected


# ── unit: _unwrap_bytes ───────────────────────────────────────────────────────


def test_unwrap_bytes_getbytes() -> None:
    assert _unwrap_bytes("signStr.getBytes()") == "signStr"


def test_unwrap_bytes_charset() -> None:
    assert _unwrap_bytes("s.getBytes(StandardCharsets.UTF_8)") == "s"


def test_unwrap_bytes_chain() -> None:
    assert _unwrap_bytes("data.trim().getBytes()") == "data.trim()"


def test_unwrap_bytes_plain() -> None:
    assert _unwrap_bytes("timestamp") == "timestamp"


# ── unit: _is_string_literal / _find_assignment ───────────────────────────────


def test_is_string_literal() -> None:
    assert _is_string_literal('"hello"')
    assert not _is_string_literal("hello")
    assert not _is_string_literal('"unterminated')


def test_find_assignment_string() -> None:
    method = 'String msg = timestamp + ":" + path;'
    assert _find_assignment("msg", method) == 'timestamp + ":" + path'


def test_find_assignment_missing() -> None:
    assert _find_assignment("ghost", "String x = 1;") is None


# ── unit: _parse_stringbuilder ────────────────────────────────────────────────


def test_parse_stringbuilder_appends() -> None:
    method = """
        StringBuilder sb = new StringBuilder();
        sb.append(timestamp);
        sb.append(":");
        sb.append(path);
        String result = sb.toString();
    """
    comps = _parse_stringbuilder("sb", method)
    assert comps is not None
    assert len(comps) == 3
    assert comps[0].kind == "timestamp"
    assert comps[1].kind == "literal" and comps[1].value == ":"
    assert comps[2].kind == "path"


def test_parse_stringbuilder_chained() -> None:
    method = """
        String s = new StringBuilder().append(ts).append(body).toString();
    """
    comps = _parse_stringbuilder("s", method)
    assert comps is not None
    kinds = [c.kind for c in comps]
    assert "timestamp" in kinds
    assert "body" in kinds


# ── integration: trace() with synthetic Java fixtures ────────────────────────


def _write(tmp_path: Path, rel: str, content: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def _usage(class_name: str, algo: str = "HMAC-SHA256") -> CryptoUsage:
    return CryptoUsage(
        algorithm=algo,
        call_site=class_name,
        context_snippet='Mac.getInstance("HmacSHA256")',
        confidence=1.0,
    )


# Pattern 1 — direct + concatenation
_JAVA_DIRECT_CONCAT = """\
package com.example.auth;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class Signer {
    private String sign(String timestamp, String path, String body) {
        String message = timestamp + "\\n" + path + "\\n" + body;
        SecretKeySpec keySpec = new SecretKeySpec(this.apiKey.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        return Base64.encode(mac.doFinal(message.getBytes()));
    }
}
"""


def test_trace_direct_concat(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _JAVA_DIRECT_CONCAT)
    usages = [_usage("com.example.auth.Signer")]
    result = trace(usages, tmp_path)
    assert len(result) == 1
    t = result[0]
    assert t.algorithm == "HMAC-SHA256"
    kinds = [c.kind for c in t.components]
    assert "timestamp" in kinds
    assert "path" in kinds
    assert "body" in kinds
    assert "literal" in kinds  # the "\n" separators


def test_trace_direct_concat_has_key_source(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _JAVA_DIRECT_CONCAT)
    result = trace([_usage("com.example.auth.Signer")], tmp_path)
    assert result[0].key_source is not None
    assert "apiKey" in result[0].key_source or "key" in result[0].key_source.lower()


def test_trace_direct_concat_high_confidence(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _JAVA_DIRECT_CONCAT)
    result = trace([_usage("com.example.auth.Signer")], tmp_path)
    assert result[0].confidence >= LLM_THRESHOLD


# Pattern 2 — StringBuilder chain
_JAVA_STRINGBUILDER = """\
package com.example.auth;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class HmacUtil {
    public String compute(String apiKey, long ts, String data) {
        StringBuilder sb = new StringBuilder();
        sb.append(apiKey);
        sb.append(ts);
        sb.append(data);
        SecretKeySpec spec = new SecretKeySpec(this.hmacKey, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(spec);
        return Hex.encode(mac.doFinal(sb.toString().getBytes()));
    }
}
"""


def test_trace_stringbuilder(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/HmacUtil.java", _JAVA_STRINGBUILDER)
    usages = [_usage("com.example.auth.HmacUtil", "HMAC-SHA1")]
    result = trace(usages, tmp_path)
    assert len(result) == 1
    kinds = [c.kind for c in result[0].components]
    assert "secret_key" in kinds or "unknown" in kinds  # apiKey → secret_key
    assert "timestamp" in kinds or "unknown" in kinds  # ts → timestamp


# Pattern 3 — multi-update
_JAVA_MULTI_UPDATE = """\
package com.example.sign;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class RequestSigner {
    private byte[] sign(String method, String path, long timestamp, String body) {
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        mac.update(String.valueOf(timestamp).getBytes());
        mac.update(method.getBytes());
        mac.update(path.getBytes());
        mac.update(body.getBytes());
        return mac.doFinal();
    }
}
"""


def test_trace_multi_update(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/sign/RequestSigner.java", _JAVA_MULTI_UPDATE)
    usages = [_usage("com.example.sign.RequestSigner")]
    result = trace(usages, tmp_path)
    assert len(result) == 1
    t = result[0]
    kinds = [c.kind for c in t.components]
    assert "timestamp" in kinds
    assert "http_method" in kinds
    assert "path" in kinds
    assert "body" in kinds


def test_trace_multi_update_ordering(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/sign/RequestSigner.java", _JAVA_MULTI_UPDATE)
    result = trace([_usage("com.example.sign.RequestSigner")], tmp_path)
    kinds = [c.kind for c in result[0].components]
    # timestamp must come before method which comes before path
    assert kinds.index("timestamp") < kinds.index("http_method")
    assert kinds.index("http_method") < kinds.index("path")


# Pattern 4 — cross-method (helper call)
_JAVA_CROSS_METHOD = """\
package com.example.auth;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class ApiAuth {
    private String buildMessage(String ts, String nonce, String path) {
        return ts + nonce + path;
    }
    public String getSignature(String ts, String nonce, String path) {
        String msg = buildMessage(ts, nonce, path);
        SecretKeySpec key = new SecretKeySpec(this.secretKey.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return Base64.encode(mac.doFinal(msg.getBytes()));
    }
}
"""


def test_trace_cross_method(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/ApiAuth.java", _JAVA_CROSS_METHOD)
    usages = [_usage("com.example.auth.ApiAuth")]
    result = trace(usages, tmp_path)
    assert len(result) == 1
    kinds = [c.kind for c in result[0].components]
    # ts → timestamp, nonce → nonce, path → path
    assert "timestamp" in kinds
    assert "nonce" in kinds
    assert "path" in kinds


# ── edge cases ────────────────────────────────────────────────────────────────


def test_trace_skips_low_confidence_usage(tmp_path: Path) -> None:
    usages = [
        CryptoUsage(
            algorithm="unknown",
            call_site="com.example.Base",
            context_snippet="import javax.crypto",
            confidence=0.4,
        )
    ]
    result = trace(usages, tmp_path)
    assert result == []


def test_trace_missing_source_file(tmp_path: Path) -> None:
    usages = [_usage("com.example.NonExistent")]
    result = trace(usages, tmp_path)
    assert len(result) == 1
    assert result[0].confidence < LLM_THRESHOLD
    assert result[0].unresolved


def test_trace_returns_signingtrace_model(tmp_path: Path) -> None:
    _write(tmp_path, "com/example/auth/Signer.java", _JAVA_DIRECT_CONCAT)
    result = trace([_usage("com.example.auth.Signer")], tmp_path)
    assert isinstance(result[0], SigningTrace)


def test_trace_unresolved_marks_low_confidence(tmp_path: Path) -> None:
    java = """\
package com.example;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class Mystery {
    private String sign() {
        String msg = buildWeirdThing();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return Base64.encode(mac.doFinal(msg.getBytes()));
    }
}
"""
    _write(tmp_path, "com/example/Mystery.java", java)
    result = trace([_usage("com.example.Mystery")], tmp_path)
    assert len(result) == 1
    # buildWeirdThing() is not defined → low confidence or unresolved
    # Accept either: low confidence OR non-empty unresolved
    t = result[0]
    assert t.confidence < 0.9 or t.unresolved


def test_signing_trace_ir_model_serialises() -> None:
    from engine.ir.models import SigningComponent, SigningTrace

    t = SigningTrace(
        algorithm="HMAC-SHA256",
        components=[
            SigningComponent(kind="timestamp", variable_name="ts"),
            SigningComponent(kind="literal", variable_name="", value=":"),
        ],
        key_source="apiKey",
        source_method="com.example.Signer.sign",
        confidence=0.87,
    )
    data = t.model_dump()
    assert data["algorithm"] == "HMAC-SHA256"
    assert len(data["components"]) == 2
    assert data["confidence"] == 0.87
