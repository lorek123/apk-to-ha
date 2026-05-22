# SPDX-License-Identifier: MIT
"""P2-5 (static path) — backward signing-input tracer.

Given CryptoUsage objects from P2-4, walks backward through decompiled Java
sources to reconstruct the signing-input format: which variables are
concatenated, in what order, and what each variable logically represents.

Works entirely on files already on disk from P1 decompilation — no LLM, no
MCP calls.  When confidence drops below LLM_THRESHOLD the SigningTrace is
still returned; the caller decides whether to escalate.

Handles:
  • Direct + concatenation:   timestamp + "\\n" + path + "\\n" + body
  • StringBuilder chains:     sb.append(ts).append(path) ... toString()
  • Multi-update patterns:    mac.update(a); mac.update(b); mac.doFinal()
  • Cross-method tracing:     variable assigned by a local helper method
                              (max depth 2, same-file search only)

Variable kind inference uses camelCase/snake_case token splitting so that
`requestPath` → "path", `httpMethod` → "http_method", `apiKey` → "secret_key".
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..ir.models import CryptoUsage, SigningComponent, SigningTrace

_LOGGER = logging.getLogger(__name__)

# Callers should escalate to LLM when confidence is below this threshold
LLM_THRESHOLD = 0.6

# ── component-kind heuristics (token-level, applied after camelCase split) ────

_KIND_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'^(timestamp|epoch|time|ts)$', re.I),          "timestamp"),
    (re.compile(r'^(nonce|rand|random)$', re.I),                "nonce"),
    (re.compile(r'^(path|url|uri|endpoint|route)$', re.I),      "path"),
    (re.compile(r'^(method|verb)$', re.I),                      "http_method"),
    (re.compile(r'^(host|domain)$', re.I),                      "host"),
    (re.compile(r'^(body|data|payload|content)$', re.I),        "body"),
    (re.compile(r'^(apikey|api|appkey|appsecret|secret|token'
                r'|accesskey|secretkey|hmackey|key)$', re.I),   "secret_key"),
]

# ── structural regexes ────────────────────────────────────────────────────────

_SECRET_KEY_RE = re.compile(r'new\s+SecretKeySpec\(\s*([^,)]+)')
_SB_DECL_RE = re.compile(r'(?:StringBuilder|StringBuffer)\s+(\w+)\s*=')
_APPEND_RE = re.compile(r'\.append\(([^)]+)\)')
_METHOD_SIG_RE = re.compile(
    r'(?:(?:private|public|protected|static|final|synchronized)\s+)*'
    r'(?:String|byte\[\]|void|boolean|int|long|Object)\s+(\w+)\s*\('
)
_ASSIGN_RE = re.compile(
    r'(?:String|byte\[\]|CharSequence|Object)\s+(\w+)\s*=\s*(.+?);',
    re.DOTALL,
)


def trace(crypto_usages: list[CryptoUsage], sources_dir: Path) -> list[SigningTrace]:
    """Return signing traces for all usages that have a traceable call site."""
    results: list[SigningTrace] = []
    for usage in crypto_usages:
        if usage.confidence < 0.5:
            _LOGGER.debug("signing_tracer: skipping low-confidence usage in %s", usage.call_site)
            continue
        t = _trace_one(usage, sources_dir)
        if t is not None:
            results.append(t)
            _LOGGER.debug(
                "signing_tracer: %s → confidence=%.2f components=%d unresolved=%d",
                t.source_method, t.confidence, len(t.components), len(t.unresolved),
            )
    return results


# ── per-usage tracer ──────────────────────────────────────────────────────────

def _trace_one(usage: CryptoUsage, sources_dir: Path) -> SigningTrace | None:
    class_file = _find_class_file(usage.call_site, sources_dir)
    if class_file is None:
        return _low_conf(usage, ["source file not found"])

    src = class_file.read_text(errors="replace")
    method_src, method_name = _find_crypto_method(src, usage.algorithm)
    if method_src is None:
        return _low_conf(usage, ["method containing crypto call not found"])

    dofinal_var, update_vars, key_var = _extract_crypto_inputs(method_src)
    fq_method = f"{usage.call_site}.{method_name}"

    # Multi-update pattern: mac.update(a); mac.update(b); mac.doFinal()
    if update_vars and not dofinal_var:
        components: list[SigningComponent] = []
        unresolved: list[str] = []
        for var in update_vars:
            c, u = _resolve_variable(var, method_src, src, sources_dir, depth=0)
            components.extend(c)
            unresolved.extend(u)
        return SigningTrace(
            algorithm=usage.algorithm, components=components, key_source=key_var,
            source_method=fq_method, confidence=_score(components, unresolved),
            unresolved=unresolved,
        )

    if dofinal_var is None:
        return _low_conf(usage, ["doFinal/update input not found"])

    components, unresolved = _resolve_variable(dofinal_var, method_src, src, sources_dir, depth=0)
    return SigningTrace(
        algorithm=usage.algorithm, components=components, key_source=key_var,
        source_method=fq_method, confidence=_score(components, unresolved),
        unresolved=unresolved,
    )


# ── source-file helpers ───────────────────────────────────────────────────────

def _find_class_file(class_name: str, sources_dir: Path) -> Path | None:
    rel = class_name.replace(".", "/") + ".java"
    candidate = sources_dir / rel
    if candidate.exists():
        return candidate
    outer = class_name.split("$")[0]
    candidate2 = sources_dir / (outer.replace(".", "/") + ".java")
    if candidate2.exists():
        return candidate2
    simple = class_name.split(".")[-1].split("$")[0] + ".java"
    for found in sources_dir.rglob(simple):
        return found
    return None


def _find_crypto_method(src: str, algorithm: str) -> tuple[str, str] | tuple[None, None]:
    lines = src.splitlines()
    target_idx: int | None = None
    for i, line in enumerate(lines):
        if ".doFinal(" in line or ".update(" in line:
            target_idx = i
            break
        if "getInstance(" in line and ("Mac" in line or "Cipher" in line):
            target_idx = i

    if target_idx is None:
        return None, None

    method_start = 0
    method_name = "unknown"
    for i in range(target_idx, -1, -1):
        m = _METHOD_SIG_RE.search(lines[i])
        if m and "{" in lines[i]:
            method_name = m.group(1)
            method_start = i
            break

    depth = 0
    method_end = target_idx
    for i in range(method_start, len(lines)):
        depth += lines[i].count("{")
        depth -= lines[i].count("}")
        method_end = i
        if depth == 0 and i > method_start:
            break

    return "\n".join(lines[method_start: method_end + 1]), method_name


def _extract_crypto_inputs(
    method_src: str,
) -> tuple[str | None, list[str], str | None]:
    """Return (dofinal_var, [update_vars], key_var) from a method body."""
    # doFinal — use paren-counting to handle nested calls like msg.getBytes()
    dofinal_var = _extract_call_arg(method_src, ".doFinal(")
    if dofinal_var is not None:
        dofinal_var = _unwrap_bytes(dofinal_var) if dofinal_var else None

    # update() calls in order of appearance
    update_vars: list[str] = []
    pos = 0
    while True:
        idx = method_src.find(".update(", pos)
        if idx < 0:
            break
        arg = _extract_call_arg(method_src, ".update(", start=idx)
        if arg:
            update_vars.append(_unwrap_conversions(_unwrap_bytes(arg)))
        pos = idx + 1

    # SecretKeySpec first argument
    key_var: str | None = None
    m = _SECRET_KEY_RE.search(method_src)
    if m:
        key_var = _unwrap_bytes(m.group(1).strip())

    return dofinal_var, update_vars, key_var


def _extract_call_arg(src: str, pattern: str, start: int = 0) -> str | None:
    """Extract the full argument of the first `pattern` call after *start*,
    respecting nested parentheses."""
    idx = src.find(pattern, start)
    if idx < 0:
        return None
    i = idx + len(pattern)
    depth = 1
    in_str = False
    escaped = False
    while i < len(src) and depth > 0:
        c = src[i]
        if escaped:
            escaped = False
        elif c == '\\' and in_str:
            escaped = True
        elif c == '"':
            in_str = not in_str
        elif not in_str:
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
        i += 1
    if depth == 0:
        return src[idx + len(pattern): i - 1].strip()
    return None


# ── variable resolution ───────────────────────────────────────────────────────

def _resolve_variable(
    expr: str,
    method_src: str,
    class_src: str,
    sources_dir: Path,
    depth: int,
) -> tuple[list[SigningComponent], list[str]]:
    expr = _unwrap_conversions(expr.strip())

    if _is_string_literal(expr):
        return [SigningComponent(kind="literal", variable_name="", value=_unquote(expr))], []

    if re.fullmatch(r'[\d.]+[Ll]?', expr):
        return [SigningComponent(kind="literal", variable_name=expr, value=expr)], []

    # Inline concatenation passed directly (e.g. as doFinal arg)
    if " + " in expr and not _is_simple_name(expr):
        return _parse_concat(expr, method_src, class_src, sources_dir, depth)

    if _is_simple_name(expr):
        # Check for StringBuilder first
        if _is_sb_variable(expr, method_src):
            comps = _parse_stringbuilder(expr, method_src)
            if comps is not None:
                return comps, []

        rhs = _find_assignment(expr, method_src)
        if rhs is not None:
            return _resolve_rhs(rhs, expr, method_src, class_src, sources_dir, depth)

        # Parameter or field — classify by name
        kind = _classify_name(expr)
        conf = 0.8 if kind != "unknown" else 0.35
        return [SigningComponent(kind=kind, variable_name=expr, confidence=conf)], (
            [] if kind != "unknown" else [expr]
        )

    kind = _classify_name(expr)
    conf = 0.5 if kind != "unknown" else 0.2
    return [SigningComponent(kind=kind, variable_name=expr, confidence=conf)], (
        [] if kind != "unknown" else [expr]
    )


def _resolve_rhs(
    rhs: str,
    var_name: str,
    method_src: str,
    class_src: str,
    sources_dir: Path,
    depth: int,
) -> tuple[list[SigningComponent], list[str]]:
    rhs = rhs.strip()

    if _is_string_literal(rhs):
        return [SigningComponent(kind="literal", variable_name=var_name, value=_unquote(rhs))], []

    if " + " in rhs:
        return _parse_concat(rhs, method_src, class_src, sources_dir, depth)

    if "new StringBuilder" in rhs or "new StringBuffer" in rhs:
        comps = _parse_stringbuilder(var_name, method_src)
        if comps is not None:
            return comps, []

    # Method call — cross-method tracing up to depth 2
    if "(" in rhs and depth < 2:
        m = re.match(r'(\w+)\(', rhs)
        if m:
            called = m.group(1)
            inner_src = _find_method_in_class(called, class_src)
            if inner_src:
                inner_dofinal, inner_updates, _ = _extract_crypto_inputs(inner_src)
                if inner_dofinal:
                    return _resolve_variable(inner_dofinal, inner_src, class_src,
                                             sources_dir, depth + 1)
                if inner_updates:
                    all_c: list[SigningComponent] = []
                    all_u: list[str] = []
                    for uv in inner_updates:
                        c, u = _resolve_variable(uv, inner_src, class_src,
                                                 sources_dir, depth + 1)
                        all_c.extend(c)
                        all_u.extend(u)
                    return all_c, all_u
                ret = re.search(r'\breturn\s+(.+?);', inner_src)
                if ret:
                    return _resolve_variable(ret.group(1).strip(), inner_src,
                                             class_src, sources_dir, depth + 1)
            return [SigningComponent(
                kind=_classify_name(var_name), variable_name=var_name, confidence=0.35,
            )], [f"{var_name}={called}(...)"]

    kind = _classify_name(var_name)
    conf = 0.75 if kind != "unknown" else 0.35
    return [SigningComponent(kind=kind, variable_name=var_name, confidence=conf)], (
        [] if kind != "unknown" else [var_name]
    )


def _parse_concat(
    expr: str,
    method_src: str,
    class_src: str,
    sources_dir: Path,
    depth: int,
) -> tuple[list[SigningComponent], list[str]]:
    parts = _split_concat(expr)
    components: list[SigningComponent] = []
    unresolved: list[str] = []
    for part in parts:
        c, u = _resolve_variable(part, method_src, class_src, sources_dir, depth)
        components.extend(c)
        unresolved.extend(u)
    return components, unresolved


def _parse_stringbuilder(sb_var: str, method_src: str) -> list[SigningComponent] | None:
    """Extract ordered components from StringBuilder append() calls."""
    # Case 1: explicit `sbVar.append(X)` calls (sequential pattern)
    explicit_pat = re.compile(r'\b' + re.escape(sb_var) + r'\.append\(([^)]+)\)')
    direct_args = explicit_pat.findall(method_src)
    if direct_args:
        return [_arg_to_component(a) for a in direct_args]

    # Case 2: `sbVar = new StringBuilder().append(x).append(y)` on one line
    chain_pat = re.compile(
        r'\b' + re.escape(sb_var) + r'\b\s*=\s*new\s+(?:StringBuilder|StringBuffer)\s*\([^)]*\)'
        r'((?:\.append\([^)]+\))+)',
    )
    m = chain_pat.search(method_src)
    if m:
        chain_args = _APPEND_RE.findall(m.group(1))
        return [_arg_to_component(a) for a in chain_args] if chain_args else None

    return None


def _arg_to_component(arg: str) -> SigningComponent:
    arg = arg.strip()
    if _is_string_literal(arg):
        return SigningComponent(kind="literal", variable_name="", value=_unquote(arg))
    clean = _unwrap_bytes(arg)
    kind = _classify_name(clean)
    conf = 0.8 if kind != "unknown" else 0.4
    return SigningComponent(kind=kind, variable_name=clean, confidence=conf)


# ── expression-level utilities ────────────────────────────────────────────────

def _split_concat(expr: str) -> list[str]:
    """Split a Java string-concatenation expression on top-level ` + `."""
    parts: list[str] = []
    depth = 0
    in_str = False
    escaped = False
    buf: list[str] = []
    i = 0
    while i < len(expr):
        c = expr[i]
        if escaped:
            buf.append(c); escaped = False; i += 1; continue
        if c == '\\' and in_str:
            buf.append(c); escaped = True; i += 1; continue
        if c == '"':
            in_str = not in_str; buf.append(c); i += 1; continue
        if in_str:
            buf.append(c); i += 1; continue
        if c in '([':
            depth += 1; buf.append(c); i += 1; continue
        if c in ')]':
            depth -= 1; buf.append(c); i += 1; continue
        if depth == 0 and c == '+' and i + 1 < len(expr) and expr[i + 1] not in ('+', '='):
            if buf:
                part = ''.join(buf).strip()
                if part:
                    parts.append(part)
                buf = []
            i += 1; continue
        buf.append(c); i += 1
    if buf:
        part = ''.join(buf).strip()
        if part:
            parts.append(part)
    return [p for p in parts if p]


def _find_assignment(var: str, method_src: str) -> str | None:
    """Return the RHS of `Type var = RHS;` in method_src."""
    pat = re.compile(
        r'(?:String|byte\[\]|CharSequence|Object)\s+' + re.escape(var) + r'\s*=\s*(.+?);',
        re.DOTALL,
    )
    m = pat.search(method_src)
    if m:
        return m.group(1).strip()
    # bare reassignment `var = RHS;`
    pat2 = re.compile(r'\b' + re.escape(var) + r'\s*=\s*(.+?);', re.DOTALL)
    m2 = pat2.search(method_src)
    if m2:
        rhs = m2.group(1).strip()
        if "{" not in rhs:
            return rhs
    return None


def _find_method_in_class(method_name: str, class_src: str) -> str | None:
    """Return the body of a named method found in class_src."""
    lines = class_src.splitlines()
    for i, line in enumerate(lines):
        if re.search(r'\b' + re.escape(method_name) + r'\s*\(', line) and \
                _METHOD_SIG_RE.search(line) and "{" in line:
            depth = 0
            for j in range(i, len(lines)):
                depth += lines[j].count("{")
                depth -= lines[j].count("}")
                if depth == 0 and j > i:
                    return "\n".join(lines[i: j + 1])
    return None


def _is_sb_variable(var: str, method_src: str) -> bool:
    explicit = re.compile(r'\b' + re.escape(var) + r'\.append\(').search(method_src)
    chain = re.compile(
        r'\b' + re.escape(var) + r'\b\s*=\s*new\s+(?:StringBuilder|StringBuffer)'
    ).search(method_src)
    return bool(explicit or chain)


def _unwrap_bytes(expr: str) -> str:
    """Strip .getBytes(...) and .encode() wrappers — nothing else."""
    expr = expr.strip()
    for pat in (
        re.compile(r'\.getBytes\([^)]*\)$'),
        re.compile(r'\.getBytes\(\)$'),
        re.compile(r'\.encode\([^)]*\)$'),
    ):
        expr = pat.sub('', expr).strip()
    return expr


def _unwrap_conversions(expr: str) -> str:
    """Strip Java type-conversion wrappers to reach the underlying variable.

    String.valueOf(timestamp) → timestamp
    Long.toString(ts)         → ts
    """
    expr = expr.strip()
    for pat in (
        re.compile(r'^String\.valueOf\((.+)\)$', re.DOTALL),
        re.compile(r'^(?:Integer|Long|Double|Float|Short|Byte)\.toString\((.+?)\)$', re.DOTALL),
        re.compile(r'^(?:Integer|Long|Double|Float)\.valueOf\((.+?)\)$', re.DOTALL),
    ):
        m = pat.match(expr)
        if m:
            return m.group(1).strip()
    return expr


def _is_string_literal(s: str) -> bool:
    s = s.strip()
    return len(s) >= 2 and s[0] == '"' and s[-1] == '"'


def _unquote(s: str) -> str:
    return s.strip().strip('"')


def _is_simple_name(s: str) -> bool:
    return bool(re.fullmatch(r'[A-Za-z_$][A-Za-z0-9_$]*', s.strip()))


# ── classification ────────────────────────────────────────────────────────────

def _split_camel(name: str) -> list[str]:
    """Split camelCase / snake_case into lowercase tokens."""
    s = re.sub(r'([a-z])([A-Z])', r'\1 \2', name)
    return [t.lower() for t in re.split(r'[_\s]+', s) if t]


def _classify_name(name: str) -> str:
    """Return kind for a variable name using camelCase token matching."""
    tokens = _split_camel(name)
    for token in tokens:
        for pattern, kind in _KIND_RULES:
            if pattern.match(token):
                return kind
    return "unknown"


# ── confidence scoring ────────────────────────────────────────────────────────

def _score(components: list[SigningComponent], unresolved: list[str]) -> float:
    if not components:
        return 0.1
    base = min(c.confidence for c in components)
    unres_ratio = len(unresolved) / max(len(components), 1)
    coverage = max(0.5, 1.0 - unres_ratio * 0.4)
    return round(max(0.05, base * coverage), 3)


def _low_conf(usage: CryptoUsage, unresolved: list[str]) -> SigningTrace:
    return SigningTrace(
        algorithm=usage.algorithm, components=[], key_source=None,
        source_method=usage.call_site, confidence=0.1, unresolved=unresolved,
    )
