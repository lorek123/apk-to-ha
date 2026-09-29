# SPDX-License-Identifier: MIT
"""Tests for P2-6 signing emitter."""

from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path
from typing import Any

from engine.extraction.signing_emitter import build
from engine.ir.models import SigningComponent, SigningTrace

# ── helpers ───────────────────────────────────────────────────────────────────


def _trace(
    algorithm: str = "HMAC-SHA256",
    components: list[SigningComponent] | None = None,
    key_source: str | None = "apiKey",
    confidence: float = 0.85,
    source_method: str = "com.example.Signer.sign",
) -> SigningTrace:
    if components is None:
        components = [
            SigningComponent(kind="timestamp", variable_name="ts"),
            SigningComponent(kind="literal", variable_name="", value="\n"),
            SigningComponent(kind="path", variable_name="path"),
            SigningComponent(kind="literal", variable_name="", value="\n"),
            SigningComponent(kind="body", variable_name="body"),
        ]
    return SigningTrace(
        algorithm=algorithm,
        components=components,
        key_source=key_source,
        source_method=source_method,
        confidence=confidence,
        unresolved=[],
    )


# ── unit: build() ─────────────────────────────────────────────────────────────


def test_build_returns_has_signing_true() -> None:
    ctx = build([_trace()])
    assert ctx["has_signing"] is True


def test_build_empty_traces() -> None:
    assert build([]) == {"has_signing": False}


def test_build_low_confidence_skipped() -> None:
    ctx = build([_trace(confidence=0.1)])
    assert ctx["has_signing"] is False


def test_build_algorithm_propagated() -> None:
    ctx = build([_trace(algorithm="HMAC-SHA1")])
    assert ctx["signing_algorithm"] == "HMAC-SHA1"
    assert ctx["signing_digest"] == "sha1"


def test_build_unknown_algorithm_defaults_to_sha256() -> None:
    ctx = build([_trace(algorithm="HMAC-RIPEMD160")])
    assert ctx["signing_digest"] == "sha256"


def test_build_params_include_timestamp_path_body() -> None:
    ctx = build([_trace()])
    names = [p["name"] for p in ctx["signing_params"]]
    assert "timestamp" in names
    assert "path" in names
    assert "body" in names


def test_build_key_param_always_present() -> None:
    ctx = build([_trace()])
    key = ctx["signing_key_param"]
    param_names = [p["name"] for p in ctx["signing_params"]]
    assert key in param_names


def test_build_key_param_is_secret_key() -> None:
    ctx = build([_trace(key_source="hmacKey")])
    assert ctx["signing_key_param"] == "secret_key"


def test_build_literal_in_message_parts() -> None:
    ctx = build([_trace()])
    kinds = [("literal" if p["is_literal"] else "var") for p in ctx["signing_message_parts"]]
    assert "literal" in kinds


def test_build_message_parts_order() -> None:
    """Parts must be in the same order as SigningTrace.components."""
    ctx = build([_trace()])
    non_literal = [p["expr"] for p in ctx["signing_message_parts"] if not p["is_literal"]]
    assert non_literal[0] in ("ts", "timestamp")
    assert "path" in non_literal
    assert "body" in non_literal


def test_build_no_duplicate_params() -> None:
    comps = [
        SigningComponent(kind="timestamp", variable_name="ts"),
        SigningComponent(kind="timestamp", variable_name="ts"),  # duplicate
        SigningComponent(kind="body", variable_name="body"),
    ]
    ctx = build([_trace(components=comps)])
    names = [p["name"] for p in ctx["signing_params"]]
    assert len(names) == len(set(names))


def test_build_picks_highest_confidence() -> None:
    low = _trace(confidence=0.4, algorithm="HMAC-SHA1")
    high = _trace(confidence=0.9, algorithm="HMAC-SHA256")
    ctx = build([low, high])
    assert ctx["signing_algorithm"] == "HMAC-SHA256"


def test_build_message_expr_is_valid_python() -> None:
    ctx = build([_trace()])
    expr = ctx["signing_message_expr"]
    # Should be a valid Python expression — eval it in a controlled env
    _SAMPLE_ARGS = {p["name"]: f"test_{p['name']}" for p in ctx["signing_params"]}
    result = eval(expr, {"_SAMPLE_ARGS": _SAMPLE_ARGS})  # noqa: S307
    assert isinstance(result, str)


def test_build_confidence_propagated() -> None:
    ctx = build([_trace(confidence=0.77)])
    assert ctx["signing_confidence"] == 0.77


# ── integration: rendered signing.py is executable ────────────────────────────


def _render_signing(ctx: dict[str, Any]) -> str:
    """Render signing.py.j2 and return the output string."""
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    tmpl_dir = Path(__file__).parents[1] / "src" / "engine" / "templates" / "sdk"
    env = Environment(
        loader=FileSystemLoader(str(tmpl_dir)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template("signing.py.j2").render(**ctx)


def test_rendered_signing_py_is_valid_python(tmp_path: Path) -> None:
    ctx = build([_trace()])
    code = _render_signing(ctx)
    # Must compile without errors
    compile(code, "<signing.py>", "exec")


def test_rendered_signing_py_function_executes_correctly(tmp_path: Path) -> None:
    ctx = build([_trace()])
    code = _render_signing(ctx)
    ns: dict[str, Any] = {}
    exec(compile(code, "<signing.py>", "exec"), ns)  # noqa: S102
    sign_fn = ns["sign"]

    ts, path, body, key = "1234567890", "/api/v1/cmd", "{}", "my_secret"
    result = sign_fn(timestamp=ts, path=path, body=body, secret_key=key)

    # Verify against Python's own hmac
    message = ts + "\n" + path + "\n" + body
    expected = base64.b64encode(
        hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    ).decode()
    assert result == expected


def test_rendered_signing_py_sha1_works(tmp_path: Path) -> None:
    ctx = build([_trace(algorithm="HMAC-SHA1")])
    code = _render_signing(ctx)
    ns: dict[str, Any] = {}
    exec(compile(code, "<signing.py>", "exec"), ns)  # noqa: S102
    sign_fn = ns["sign"]

    ts, path, body, key = "ts", "/path", "body", "key"
    result = sign_fn(timestamp=ts, path=path, body=body, secret_key=key)

    message = ts + "\n" + path + "\n" + body
    expected = base64.b64encode(
        hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha1).digest()
    ).decode()
    assert result == expected


def test_rendered_signing_py_has_spdx_header() -> None:
    ctx = build([_trace()])
    code = _render_signing(ctx)
    assert "SPDX-License-Identifier: MIT" in code


# ── integration: rendered test_signing.py is valid Python ─────────────────────


def _render_test(ctx: dict[str, Any]) -> str:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined

    tmpl_dir = Path(__file__).parents[1] / "src" / "engine" / "templates" / "sdk"
    env = Environment(
        loader=FileSystemLoader(str(tmpl_dir)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template("tests/test_signing.py.j2").render(**ctx)


def test_rendered_test_signing_py_compiles(tmp_path: Path) -> None:
    ctx = {**build([_trace()]), "domain": "mydevice", "sdk_package": "mydevice_sdk"}
    code = _render_test(ctx)
    compile(code, "<test_signing.py>", "exec")


def test_rendered_test_signing_contains_reference_hmac_test() -> None:
    ctx = {**build([_trace()]), "domain": "mydevice", "sdk_package": "mydevice_sdk"}
    code = _render_test(ctx)
    assert "test_sign_matches_reference_hmac" in code


def test_rendered_test_signing_has_spdx() -> None:
    ctx = {**build([_trace()]), "domain": "mydevice", "sdk_package": "mydevice_sdk"}
    code = _render_test(ctx)
    assert "SPDX-License-Identifier: MIT" in code


# ── sdk_emitter integration ───────────────────────────────────────────────────


def test_sdk_emitter_creates_signing_py_when_has_signing(tmp_path: Path) -> None:
    from engine.emitters.sdk_emitter import emit
    from engine.extraction.signing_emitter import build as build_signing

    ctx = {
        "domain": "testdev",
        "name": "Test Device",
        "class_prefix": "Testdev",
        "sdk_package": "testdev_sdk",
        "integration_version": "0.1.0",
        "ha_min_version": "2024.1.0",
        "iot_class": "local_polling",
        "app_description": "",
        "app_summary": "",
        "play_category": "",
        "play_developer": "",
        "ws_port": 8887,
        "udp_port": None,
        "udp_broadcast_cmd": None,
        "auth_cmd": "grantAccess",
        "auth_result_field": None,
        "state_push_cmd": "gin",
        "switches": [],
        "buttons": [],
        "selects": [],
        "numbers": [],
        "sensors": [],
        "binary_sensors": [],
        "model_sensors": [],
        "model_binary_sensors": [],
        "mode_actions": {},
        "platforms": [],
        **build_signing([_trace()]),
    }
    sdk_dir = emit(ctx, tmp_path)
    assert (sdk_dir / "signing.py").exists()
    assert (tmp_path / "tests" / "test_signing.py").exists()


def test_sdk_emitter_skips_signing_when_no_traces(tmp_path: Path) -> None:
    from engine.emitters.sdk_emitter import emit

    ctx = {
        "domain": "testdev",
        "name": "Test Device",
        "class_prefix": "Testdev",
        "sdk_package": "testdev_sdk",
        "integration_version": "0.1.0",
        "ha_min_version": "2024.1.0",
        "iot_class": "local_polling",
        "app_description": "",
        "app_summary": "",
        "play_category": "",
        "play_developer": "",
        "ws_port": 8887,
        "udp_port": None,
        "udp_broadcast_cmd": None,
        "auth_cmd": "grantAccess",
        "auth_result_field": None,
        "state_push_cmd": "gin",
        "switches": [],
        "buttons": [],
        "selects": [],
        "numbers": [],
        "sensors": [],
        "binary_sensors": [],
        "model_sensors": [],
        "model_binary_sensors": [],
        "mode_actions": {},
        "platforms": [],
        "has_signing": False,
    }
    sdk_dir = emit(ctx, tmp_path)
    assert not (sdk_dir / "signing.py").exists()
