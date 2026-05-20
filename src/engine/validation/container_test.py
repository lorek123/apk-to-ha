# SPDX-License-Identifier: MIT
"""V-3 — HA container import test.

Spins up the pinned HA Docker image, installs the generated SDK, then
tries to import the integration's async_setup_entry via PYTHONPATH injection.
Catches import-time errors (missing symbols, bad syntax the AST missed,
circular imports) without needing a real HA config or device.

Skipped gracefully when Docker is unavailable.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import tomllib
from dataclasses import dataclass
from pathlib import Path

_LOGGER = logging.getLogger(__name__)
_HA_TARGET = Path(__file__).parents[3] / "config" / "ha_target.toml"

_IMPORT_SCRIPT = """\
import sys, importlib, pathlib
# Confirm async_setup_entry is importable
mod = importlib.import_module("custom_components.{domain}")
assert hasattr(mod, "async_setup_entry"), "missing async_setup_entry"
print("V3_IMPORT_OK")
"""


@dataclass
class ContainerTestResult:
    ran: bool          # False when Docker unavailable — test skipped
    passed: bool
    output: str
    error: str = ""


async def run(domain: str, sdk_output_dir: Path) -> ContainerTestResult:
    """Run the container import test. Returns result (skipped if no Docker)."""
    if not shutil.which("docker"):
        _LOGGER.info("Docker not found — V-3 container test skipped")
        return ContainerTestResult(ran=False, passed=True, output="skipped")

    with open(_HA_TARGET, "rb") as fh:
        cfg = tomllib.load(fh)
    tag = cfg["docker"]["ha_image_tag"]
    image = f"homeassistant/home-assistant:{tag}"

    # sdk_output_dir layout: {sdk_package}/ pyproject.toml custom_components/{domain}/
    sdk_pkg_dir = next(
        (d for d in sdk_output_dir.iterdir() if d.is_dir() and not d.name.startswith("custom")),
        None,
    )

    script = _IMPORT_SCRIPT.format(domain=domain)

    # Build docker command: install SDK from mounted dir, then run import script
    install_cmd = f"pip install -q /out/{sdk_pkg_dir.name}/.." if sdk_pkg_dir else "true"
    full_cmd = f"{install_cmd} && PYTHONPATH=/out python3 -c '{script}'"

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{sdk_output_dir.resolve()}:/out:ro",
        image,
        "sh", "-c", full_cmd,
    ]

    _LOGGER.info("V-3: docker run %s (import test for %s)", image, domain)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode()
        passed = "V3_IMPORT_OK" in output and (proc.returncode or 0) == 0
        _LOGGER.info("V-3: %s (rc=%d)", "PASS" if passed else "FAIL", proc.returncode or 0)
        return ContainerTestResult(ran=True, passed=passed, output=output)
    except asyncio.TimeoutError:
        return ContainerTestResult(ran=True, passed=False,
                                   output="", error="Container test timed out after 120s")
    except Exception as exc:
        return ContainerTestResult(ran=True, passed=False, output="", error=str(exc))
