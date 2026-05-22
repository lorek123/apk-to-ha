# SPDX-License-Identifier: MIT
"""P2-6 — translate a SigningTrace into a Jinja2 context for signing.py.j2 / test_signing.py.j2.

No code is rendered here; this module only builds the dict that the templates consume.
"""
from __future__ import annotations

import re

from ..ir.models import SigningTrace

# Minimum confidence for the trace to be rendered; below this we skip.
_MIN_CONFIDENCE = 0.3

_ALGO_TO_DIGEST: dict[str, str] = {
    "HMAC-SHA256": "sha256",
    "HMAC-SHA1": "sha1",
    "HMAC-SHA384": "sha384",
    "HMAC-SHA512": "sha512",
    "HMAC-MD5": "md5",
}

# Maps component kind → preferred Python parameter name
_KIND_TO_PARAM: dict[str, str] = {
    "timestamp": "timestamp",
    "nonce": "nonce",
    "path": "path",
    "http_method": "method",
    "host": "host",
    "body": "body",
    "secret_key": "secret_key",
    "unknown": "param",
}


def build(traces: list[SigningTrace]) -> dict:
    """Return a context dict consumed by signing.py.j2 and test_signing.py.j2.

    If no suitable trace exists, returns ``{"has_signing": False}``.
    """
    if not traces:
        return {"has_signing": False}

    best = max(traces, key=lambda t: t.confidence)
    if best.confidence < _MIN_CONFIDENCE:
        return {"has_signing": False}

    digest = _ALGO_TO_DIGEST.get(best.algorithm.upper(), "sha256")

    # ── build deduplicated parameter list and message parts ──────────────────
    params: list[dict] = []
    seen: set[str] = set()
    message_parts: list[dict] = []

    _unknown_counter = 0

    for comp in best.components:
        if comp.kind == "literal":
            message_parts.append({"is_literal": True, "expr": repr(comp.value or "")})
        else:
            param_name = _resolve_param_name(comp.kind, comp.variable_name, seen)
            if comp.kind == "unknown":
                _unknown_counter += 1
                param_name = f"param_{_unknown_counter}"
            if param_name not in seen:
                params.append({"name": param_name, "type_hint": "str"})
                seen.add(param_name)
            message_parts.append({"is_literal": False, "expr": param_name})

    # key param — always last and always present
    key_param = _resolve_param_name("secret_key", best.key_source or "secret_key", seen)
    if key_param not in seen:
        params.append({"name": key_param, "type_hint": "str"})
        seen.add(key_param)

    # ── pre-build the message concat expression for the reference HMAC test ──
    signing_message_expr = _build_message_expr(message_parts)

    return {
        "has_signing": True,
        "signing_algorithm": best.algorithm,
        "signing_digest": digest,
        "signing_params": params,
        "signing_key_param": key_param,
        "signing_message_parts": message_parts,
        "signing_message_expr": signing_message_expr,
        "signing_confidence": round(best.confidence, 3),
        "signing_source_method": best.source_method,
    }


# ── helpers ───────────────────────────────────────────────────────────────────

def _resolve_param_name(kind: str, variable_name: str | None, seen: set[str]) -> str:
    """Return a clean Python identifier for this component.

    For known kinds the canonical name wins — keeps the generated signature
    readable regardless of what the decompiled variable was called.
    For ``unknown`` kind we fall back to the original variable name.
    """
    preferred = _KIND_TO_PARAM.get(kind, "param")
    if kind != "unknown":
        return preferred
    # unknown kind: try to use the original variable name as a readable hint
    if variable_name and re.fullmatch(r"[a-z_][a-z0-9_]*", variable_name.lower()):
        candidate = variable_name.lower()
        if candidate not in seen:
            return candidate
    return preferred


def _build_message_expr(message_parts: list[dict]) -> str:
    """Return a Python expression that reconstructs the message from _SAMPLE_ARGS."""
    pieces: list[str] = []
    for part in message_parts:
        if part["is_literal"]:
            pieces.append(part["expr"])  # already repr'd
        else:
            pieces.append(f'_SAMPLE_ARGS["{part["expr"]}"]')
    return " + ".join(pieces) if pieces else '""'
