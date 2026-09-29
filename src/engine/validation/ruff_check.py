# SPDX-License-Identifier: MIT
"""V-1 — Ruff lint check on generated Python files.

Runs ruff with a relaxed rule set appropriate for generated code:
  - E/F/W: syntax + obvious errors
  - I: import ordering (isort)
  - Skips: line-length (generated code can be verbose), complexity rules
Returns structured findings so the pipeline can surface them.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

# Rules relevant to generated code; omit opinionated style rules
_RUFF_SELECT = "E,F,W,I"
_RUFF_IGNORE = "E501"  # line-length — generated lines can be long


@dataclass
class RuffFinding:
    file: str
    line: int
    col: int
    code: str
    message: str


@dataclass
class RuffResult:
    passed: bool
    error_count: int
    warning_count: int
    findings: list[RuffFinding] = field(default_factory=list)
    tool_error: str = ""  # non-empty when ruff itself failed (rc=2 / unparseable output)


async def check(path: Path) -> RuffResult:
    """Run ruff on *path* (file or directory). Returns structured result."""
    proc = await asyncio.create_subprocess_exec(
        "ruff",
        "check",
        "--select",
        _RUFF_SELECT,
        "--ignore",
        _RUFF_IGNORE,
        "--output-format",
        "json",
        str(path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    # Ruff rc=0 means no issues; rc=1 means findings; rc=2 means tool error
    if proc.returncode not in (0, 1):
        msg = stderr.decode().strip()[:500] or f"ruff exited with rc={proc.returncode}"
        _LOGGER.error("ruff failed on %s: %s", path, msg)
        return RuffResult(passed=False, error_count=0, warning_count=0, tool_error=msg)
    try:
        raw = json.loads(stdout.decode()) if stdout.strip() else []
    except json.JSONDecodeError as exc:
        _LOGGER.error("ruff output on %s is not JSON: %s", path, exc)
        return RuffResult(
            passed=False, error_count=0, warning_count=0, tool_error=f"unparseable output: {exc}"
        )

    findings = [
        RuffFinding(
            file=e.get("filename", ""),
            line=e.get("location", {}).get("row", 0),
            col=e.get("location", {}).get("column", 0),
            code=e.get("code", ""),
            message=e.get("message", ""),
        )
        for e in raw
    ]

    errors = [f for f in findings if not f.code.startswith("W")]
    warnings = [f for f in findings if f.code.startswith("W")]

    _LOGGER.info(
        "ruff: %d errors, %d warnings in %s",
        len(errors),
        len(warnings),
        path.name,
    )
    return RuffResult(
        passed=len(errors) == 0,
        error_count=len(errors),
        warning_count=len(warnings),
        findings=findings,
    )
