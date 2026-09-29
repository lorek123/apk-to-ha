# SPDX-License-Identifier: MIT
"""V-3 — HA container test.

Two modes, strongest available first:

``runtime``  The sandbox image (``make sandbox``) has pytest-homeassistant-custom-component
             for the pinned HA version. The generated ``tests/`` run the integration in a
             real ``hass``: config flow, setup, entity creation, push updates, reconnect,
             unload — against a mock device speaking the extracted protocol.
``import``   Fallback on the bare HA image: only checks that the integration imports.
             Reported via ``mode`` so the run status can flag the weaker check.

Skipped (``ran=False, passed=None``) when Docker is unavailable.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

_LOGGER = logging.getLogger(__name__)
_HA_TARGET = Path(__file__).parents[3] / "config" / "ha_target.toml"

# Docker label the sandbox image carries (see docker/sandbox/Dockerfile).
PHCC_LABEL = "org.hacs-engine.phcc-version"

_RUNTIME_TIMEOUT = 600
_IMPORT_TIMEOUT = 120

_IMPORT_SCRIPT = """\
import importlib
mod = importlib.import_module("custom_components.{domain}")
assert hasattr(mod, "async_setup_entry"), "missing async_setup_entry"
print("V3_IMPORT_OK")
"""

Mode = Literal["runtime", "import", "skipped"]


@dataclass
class ContainerTestResult:
    ran: bool  # False when Docker unavailable — test skipped
    passed: bool | None  # None when skipped: a skip is not a pass
    output: str
    error: str = ""
    mode: Mode = "skipped"


def _load_target() -> dict[str, Any]:
    with open(_HA_TARGET, "rb") as fh:
        return tomllib.load(fh)


def _image_label(image: str, label: str) -> str | None:
    """Return *label* of a local image, or None if the image doesn't exist locally."""
    result = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            f'{{{{index .Config.Labels "{label}"}}}}',
            image,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _resolve_image(cfg: dict[str, Any]) -> tuple[str, Mode]:
    """Pick the sandbox image when it matches the pinned phcc version, else bare HA."""
    sandbox = cfg.get("sandbox", {})
    full_sandbox = f"{sandbox.get('image', 'hacs-engine-sandbox')}:{sandbox.get('tag', 'latest')}"
    want = sandbox.get("phcc_version")

    have = _image_label(full_sandbox, PHCC_LABEL)
    if want and have == want:
        _LOGGER.info("V-3: runtime tests in %s (phcc %s)", full_sandbox, have)
        return full_sandbox, "runtime"
    if have is not None:
        _LOGGER.warning(
            "V-3: %s has phcc %r but %r is pinned — run `make sandbox`", full_sandbox, have, want
        )

    fallback = f"{cfg['docker']['ha_image']}:{cfg['docker']['ha_image_tag']}"
    _LOGGER.warning("V-3: sandbox unavailable — import-only check with %s", fallback)
    return fallback, "import"


def _prepare(out_dir: Path) -> tuple[str, Mode, bool, Path]:
    """Blocking setup for run(): image + mode, whether tests exist, mount path."""
    image, mode = _resolve_image(_load_target())
    return image, mode, (out_dir / "tests").is_dir(), out_dir.resolve()


async def run(domain: str, out_dir: Path) -> ContainerTestResult:
    """Run V-3 on *out_dir* (SDK package + custom_components/ + tests/)."""
    if not shutil.which("docker"):
        _LOGGER.info("Docker not found — V-3 container test skipped")
        return ContainerTestResult(ran=False, passed=None, output="skipped")

    image, mode, has_tests, mount = await asyncio.to_thread(_prepare, out_dir)
    if mode == "runtime" and not has_tests:
        _LOGGER.warning("V-3: no generated tests/ — falling back to import-only check")
        mode = "import"

    # Work on a writable copy; the SDK package and custom_components/ both sit at the
    # root, so PYTHONPATH makes them importable without installing anything.
    if mode == "runtime":
        script = "python3 -m pytest -q -p no:cacheprovider tests"
        timeout = _RUNTIME_TIMEOUT
    else:
        script = f"python3 -c '{_IMPORT_SCRIPT.format(domain=domain)}'"
        timeout = _IMPORT_TIMEOUT
    full_cmd = f"cp -r /out /tmp/work && cd /tmp/work && PYTHONPATH=/tmp/work {script}"

    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "sh",
        "-v",
        f"{mount}:/out:ro",
        image,
        "-c",
        full_cmd,
    ]

    _LOGGER.info("V-3: %s test for %s in %s", mode, domain, image)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except OSError as exc:
        return ContainerTestResult(ran=True, passed=False, output="", error=str(exc), mode=mode)
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return ContainerTestResult(
            ran=True, passed=False, output="", error=f"timed out after {timeout}s", mode=mode
        )

    output = stdout.decode(errors="replace")
    rc = proc.returncode or 0
    passed = rc == 0 and (mode == "runtime" or "V3_IMPORT_OK" in output)
    _LOGGER.info("V-3: %s (%s, rc=%d)", "PASS" if passed else "FAIL", mode, rc)
    return ContainerTestResult(ran=True, passed=passed, output=output, mode=mode)
