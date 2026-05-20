# SPDX-License-Identifier: MIT
"""F-0a — ha-tooling MCP server.

Exposes run_ruff, run_mypy, run_hassfest, run_pytest as MCP tools.
Each returns structured JSON, not raw stderr.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import sys
from pathlib import Path

import tomllib
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ha-tooling")

_REPO_ROOT = Path(__file__).parents[2]
_HA_CORE_DIR = _REPO_ROOT / ".cache" / "ha-core"
_HA_TARGET = _REPO_ROOT / "config" / "ha_target.toml"


def _ha_image_tag() -> str:
    with open(_HA_TARGET, "rb") as fh:
        cfg = tomllib.load(fh)
    return cfg["docker"]["ha_image_tag"]


async def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode or 0, stdout.decode(), stderr.decode()


# ── ruff ───────────────────────────────────────────────────────────────────────

@mcp.tool()
async def run_ruff(path: str, fix: bool = False) -> dict:
    """Run ruff linter on path. Returns {success, error_count, errors[]}."""
    cmd = ["ruff", "check", "--output-format=json"]
    if fix:
        cmd.append("--fix")
    cmd.append(path)

    rc, stdout, stderr = await _run(cmd)
    try:
        raw = json.loads(stdout) if stdout.strip() else []
    except json.JSONDecodeError:
        raw = []

    errors = [
        {
            "file": e.get("filename"),
            "line": e.get("location", {}).get("row"),
            "col": e.get("location", {}).get("column"),
            "code": e.get("code"),
            "message": e.get("message"),
        }
        for e in raw
    ]
    return {"success": rc == 0, "error_count": len(errors), "errors": errors}


# ── mypy ───────────────────────────────────────────────────────────────────────

@mcp.tool()
async def run_mypy(path: str) -> dict:
    """Run mypy --strict on path. Returns {success, error_count, errors[]}."""
    cmd = [sys.executable, "-m", "mypy", "--strict", "--no-error-summary", path]
    rc, stdout, _ = await _run(cmd)

    errors = []
    for line in stdout.splitlines():
        m = re.match(r"^(.+?):(\d+):\s*(error|warning|note):\s*(.+)$", line)
        if m:
            errors.append({
                "file": m.group(1),
                "line": int(m.group(2)),
                "severity": m.group(3),
                "message": m.group(4),
            })

    return {"success": rc == 0, "error_count": len(errors), "errors": errors}


# ── hassfest ───────────────────────────────────────────────────────────────────

@mcp.tool()
async def run_hassfest(integration_path: str) -> dict:
    """Run hassfest against a custom_components integration directory.

    Tries HA Core clone first; falls back to Docker if unavailable.
    Returns {success, error_count, errors[]}.
    """
    int_path = Path(integration_path).resolve()

    if _HA_CORE_DIR.exists():
        return await _hassfest_local(int_path)
    return await _hassfest_docker(int_path)


async def _hassfest_local(int_path: Path) -> dict:
    cmd = [
        sys.executable, "-m", "script.hassfest",
        "--integration-path", str(int_path),
        "--action", "validate",
    ]
    rc, stdout, stderr = await _run(cmd, cwd=_HA_CORE_DIR)
    combined = stdout + stderr
    return _parse_hassfest_output(rc, combined)


async def _hassfest_docker(int_path: Path) -> dict:
    tag = _ha_image_tag()
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{int_path}:/tmp/integration:ro",
        f"homeassistant/home-assistant:{tag}",
        "python3", "-m", "script.hassfest",
        "--integration-path", "/tmp/integration",
        "--action", "validate",
    ]
    rc, stdout, stderr = await _run(cmd)
    return _parse_hassfest_output(rc, stdout + stderr)


def _parse_hassfest_output(rc: int, output: str) -> dict:
    errors = []
    for line in output.splitlines():
        if "ERROR" in line or "Invalid" in line or "failed" in line.lower():
            errors.append({"message": line.strip()})
    return {"success": rc == 0, "error_count": len(errors), "errors": errors, "raw": output}


# ── pytest ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def run_pytest(path: str, test_path: str | None = None) -> dict:
    """Run pytest. Returns {success, passed, failed, errors[]}."""
    target = test_path or path
    cmd = [sys.executable, "-m", "pytest", target, "--tb=short", "-q", "--json-report", "--json-report-file=/tmp/pytest_report.json"]
    rc, stdout, stderr = await _run(cmd, cwd=Path(path))

    # Parse summary line: "X passed, Y failed in Zs"
    passed = failed = 0
    m = re.search(r"(\d+) passed", stdout + stderr)
    if m:
        passed = int(m.group(1))
    m = re.search(r"(\d+) failed", stdout + stderr)
    if m:
        failed = int(m.group(1))

    # Try to read JSON report for structured errors
    errors = []
    try:
        report = json.loads(Path("/tmp/pytest_report.json").read_text())
        for t in report.get("tests", []):
            if t.get("outcome") == "failed":
                errors.append({
                    "test": t.get("nodeid"),
                    "message": t.get("call", {}).get("longrepr", ""),
                })
    except Exception:
        pass

    return {"success": rc == 0, "passed": passed, "failed": failed, "errors": errors}


if __name__ == "__main__":
    mcp.run()
