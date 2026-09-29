# SPDX-License-Identifier: MIT
"""P2-4 — Crypto API scanner.

Walks decompiled Java/Kotlin source files and identifies usage of cryptographic
primitives. Output feeds P2-5 (signing-input tracer) and informs auth scheme
detection (HMAC-signed requests look different from plain API-key headers).

Detection targets:
  - javax.crypto.Mac.getInstance(...)  → HMAC-*
  - java.security.MessageDigest.getInstance(...)  → SHA-*/MD5
  - javax.crypto.Cipher.getInstance(...)  → AES/*, RSA/*
  - javax.crypto.spec.SecretKeySpec(...)  → key material for above
  - Common third-party idioms: OkHttp RequestBody signing, Apache Commons
    HmacUtils, Tink primitives
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..ir.models import CryptoUsage as CryptoUsage

_LOGGER = logging.getLogger(__name__)

# Patterns for getInstance("...") calls — capture the algorithm string
_GETINSTANCE = re.compile(
    r"(?:Mac|MessageDigest|Cipher|KeyGenerator|KeyAgreement|Signature|KeyPairGenerator)"
    r'\.getInstance\(\s*"([^"]+)"',
)
# SecretKeySpec(key, "AES") — capture the algorithm
_SECRET_KEY_SPEC = re.compile(r'SecretKeySpec\([^,]+,\s*"([^"]+)"')
# String literals that look like algorithm names
_ALGO_LITERAL = re.compile(
    r'"(HmacSHA(?:256|1|512)|HMAC[-_]SHA(?:256|1|512)|AES(?:/[A-Z0-9/]+)?'
    r'|SHA-?(?:256|1|512)|MD5|RSA(?:/[A-Z0-9/]+)?)"',
    re.IGNORECASE,
)
# import lines that indicate crypto usage
_IMPORT_CRYPTO = re.compile(
    r"import\s+(javax\.crypto\.|java\.security\.MessageDigest"
    r"|org\.apache\.commons\.codec\.digest"
    r"|com\.google\.crypto\.tink)"
)


def scan(sources_dir: Path) -> list[CryptoUsage]:
    """Return all crypto usages found under *sources_dir*."""
    usages: list[CryptoUsage] = []
    seen: set[tuple[str, str]] = set()

    for java_file in sources_dir.rglob("*.java"):
        _scan_file(java_file, sources_dir, usages, seen)

    _LOGGER.debug("crypto_scanner: found %d usages in %s", len(usages), sources_dir)
    return usages


def _scan_file(
    path: Path,
    root: Path,
    out: list[CryptoUsage],
    seen: set[tuple[str, str]],
) -> None:
    try:
        src = path.read_text(errors="replace")
    except OSError:
        return

    if not (_IMPORT_CRYPTO.search(src) or _GETINSTANCE.search(src) or _SECRET_KEY_SPEC.search(src)):
        return  # fast-path: no crypto

    class_name = _infer_class(path, root)
    lines = src.splitlines()

    for i, line in enumerate(lines):
        algo = _extract_algorithm(line)
        if algo is None:
            continue
        algo_norm = _normalise(algo)
        key = (class_name, algo_norm)
        if key in seen:
            continue
        seen.add(key)

        snippet = "\n".join(lines[max(0, i - 1) : i + 3])
        out.append(
            CryptoUsage(
                algorithm=algo_norm,
                call_site=class_name,
                context_snippet=snippet[:500],
            )
        )

    # Low-confidence pass: if file imports crypto but no specific call found
    if _IMPORT_CRYPTO.search(src) and not any(u.call_site == class_name for u in out):
        m = _IMPORT_CRYPTO.search(src)
        pkg = m.group(1).rstrip(".") if m else "javax.crypto"
        key = (class_name, pkg)
        if key not in seen:
            seen.add(key)
            out.append(
                CryptoUsage(
                    algorithm="unknown",
                    call_site=class_name,
                    context_snippet=f"import {pkg}",
                    confidence=0.4,
                )
            )


def _extract_algorithm(line: str) -> str | None:
    """Return the algorithm string from a single line, or None."""
    m = _GETINSTANCE.search(line)
    if m:
        return m.group(1)
    m = _SECRET_KEY_SPEC.search(line)
    if m:
        return m.group(1)
    m = _ALGO_LITERAL.search(line)
    if m:
        return m.group(1)
    return None


def _normalise(algo: str) -> str:
    """Normalise algorithm string to a canonical form."""
    a = algo.upper().replace("_", "-").replace(" ", "-")
    # HmacSHA256 → HMAC-SHA256
    a = re.sub(r"^HMAC([A-Z])", r"HMAC-\1", a)
    # SHA256 → SHA-256
    a = re.sub(r"^SHA(\d+)$", r"SHA-\1", a)
    return a


def _infer_class(path: Path, root: Path) -> str:
    """Derive a dot-separated class name from the file path."""
    try:
        rel = path.relative_to(root)
        # sources/com/example/Foo.java → com.example.Foo
        parts = list(rel.parts)
        if parts and parts[0] in ("sources", "src", "java"):
            parts = parts[1:]
        return ".".join(parts).removesuffix(".java")
    except ValueError:
        return path.stem
