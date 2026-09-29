# SPDX-License-Identifier: MIT
"""V-7 — HA log analyzer.

Parses container output from V-3 into structured findings. Categories mirror
the HA developer docs quality-scale failure modes:

  import_error    — Python traceback during module import (always error)
  setup_failure   — HA ConfigEntry setup failure (error)
  async_violation — Blocking call detected in event loop (warning)
  deprecation     — Deprecated API usage (warning)
  schema_error    — Config / vol.Schema / pydantic validation error (error)
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class LogFinding:
    category: str  # see module docstring
    severity: str  # "error" | "warning"
    message: str  # human-readable summary
    raw_line: str  # original log line


# ── detection patterns ────────────────────────────────────────────────────────

_IMPORT_ERROR = re.compile(
    r"(Traceback \(most recent|ImportError|ModuleNotFoundError|SyntaxError"
    r"|AttributeError: module|NameError:|TypeError:|cannot import name)",
)
_SETUP_FAILURE = re.compile(
    r"(Setup failed for|ConfigEntryNotReady|Error setting up integration"
    r"|Platform .+ not ready|async_setup_entry .+ failed)",
    re.IGNORECASE,
)
_ASYNC_VIOLATION = re.compile(
    r"(Detected blocking call to|Blocking call to .+ in the event loop)",
    re.IGNORECASE,
)
_DEPRECATION = re.compile(
    r"(was deprecated in HA Core|DeprecationWarning|is deprecated)",
    re.IGNORECASE,
)
_SCHEMA_ERROR = re.compile(
    r"(Invalid config|required key not provided|extra keys not allowed"
    r"|voluptuous\.error\.|ValidationError|schema validation failed)",
    re.IGNORECASE,
)

_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (_IMPORT_ERROR, "import_error", "error"),
    (_SETUP_FAILURE, "setup_failure", "error"),
    (_ASYNC_VIOLATION, "async_violation", "warning"),
    (_DEPRECATION, "deprecation", "warning"),
    (_SCHEMA_ERROR, "schema_error", "error"),
]


def analyze(container_output: str) -> list[LogFinding]:
    """Parse *container_output* from V-3 and return structured findings.

    Lines are deduped within the same category to avoid repeated-traceback noise.
    """
    findings: list[LogFinding] = []
    seen: set[tuple[str, str]] = set()

    for line in container_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        for pattern, category, severity in _RULES:
            if pattern.search(stripped):
                key = (category, stripped[:120])
                if key in seen:
                    break
                seen.add(key)
                findings.append(
                    LogFinding(
                        category=category,
                        severity=severity,
                        message=_summarise(category, stripped),
                        raw_line=stripped,
                    )
                )
                break  # one finding per line

    return findings


def summary(findings: list[LogFinding]) -> dict[str, int]:
    """Return finding counts keyed by category."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    return counts


# ── internal helpers ──────────────────────────────────────────────────────────


def _summarise(category: str, line: str) -> str:
    """Return a short human-readable message for a finding."""
    if category == "import_error":
        return f"Import error: {line[:120]}"
    if category == "setup_failure":
        return f"Setup failure: {line[:120]}"
    if category == "async_violation":
        return f"Async violation: {line[:120]}"
    if category == "deprecation":
        return f"Deprecated API: {line[:120]}"
    if category == "schema_error":
        return f"Schema error: {line[:120]}"
    return line[:120]
