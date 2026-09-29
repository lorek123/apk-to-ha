# SPDX-License-Identifier: MIT
"""Lifecycle management for the redroid Android Docker container.

Requires:
  - Docker daemon running
  - `binder_linux` kernel module (auto-loaded if absent)
  - redroid image: redroid/redroid:13.0.0-latest

The container is started with --privileged so the entrypoint can create
/dev/binder, /dev/ashmem, and related devices automatically.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

_LOGGER = logging.getLogger(__name__)

_REDROID_IMAGE = "redroid/redroid:13.0.0-latest"
_ADB_PORT = 5555
_FRIDA_PORT = 27042
_BOOT_TIMEOUT = 120  # seconds to wait for Android to finish booting
_POLL_INTERVAL = 3  # seconds between boot-check polls


class RedroidUnavailableError(Exception):
    """Raised when redroid cannot be started (missing kernel module, no Docker, etc.)."""


async def ensure_binder_module() -> None:
    """Load binder_linux if not already present."""
    proc = await asyncio.create_subprocess_exec(
        "lsmod",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    if b"binder_linux" in stdout:
        return
    _LOGGER.info("redroid: loading binder_linux kernel module")
    result = await asyncio.create_subprocess_exec(
        "modprobe",
        "binder_linux",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await result.communicate()
    if result.returncode != 0:
        raise RedroidUnavailableError(f"binder_linux modprobe failed: {stderr.decode().strip()}")


async def pull_image_if_absent() -> None:
    """Pull the redroid image if not already present locally."""
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "image",
        "inspect",
        _REDROID_IMAGE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()
    if proc.returncode == 0:
        return  # already present

    _LOGGER.info("redroid: pulling %s (first run, may take a few minutes)", _REDROID_IMAGE)
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "pull",
        _REDROID_IMAGE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    await proc.communicate()
    if proc.returncode != 0:
        raise RedroidUnavailableError(f"docker pull {_REDROID_IMAGE} failed")


async def start_container(container_name: str = "hacs-engine-redroid") -> str:
    """Start the redroid container and return its ID."""
    # Remove stale container with the same name
    await asyncio.create_subprocess_exec(
        "docker",
        "rm",
        "-f",
        container_name,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    proc = await asyncio.create_subprocess_exec(
        "docker",
        "run",
        "-d",
        "--privileged",
        "--name",
        container_name,
        "-p",
        f"{_ADB_PORT}:{_ADB_PORT}",
        "-p",
        f"{_FRIDA_PORT}:{_FRIDA_PORT}",
        _REDROID_IMAGE,
        "androidboot.redroid_width=1080",
        "androidboot.redroid_height=1920",
        "androidboot.redroid_fps=30",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RedroidUnavailableError(f"docker run failed: {stderr.decode().strip()}")
    container_id = stdout.decode().strip()
    _LOGGER.info("redroid: container started (%s)", container_id[:12])
    return container_id


async def wait_for_boot(container_id: str) -> None:
    """Poll until Android reports sys.boot_completed=1 or timeout."""
    deadline = time.monotonic() + _BOOT_TIMEOUT
    while time.monotonic() < deadline:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "exec",
            container_id,
            "getprop",
            "sys.boot_completed",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await proc.communicate()
        if stdout.decode().strip() == "1":
            _LOGGER.info("redroid: Android boot complete")
            return
        await asyncio.sleep(_POLL_INTERVAL)
    raise RedroidUnavailableError("Android did not boot within timeout")


async def stop_container(container_id: str) -> None:
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "rm",
        "-f",
        container_id,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.communicate()
    _LOGGER.debug("redroid: container removed (%s)", container_id[:12])


@asynccontextmanager
async def redroid(container_name: str = "hacs-engine-redroid") -> AsyncIterator[str]:
    """Async context manager: start redroid, yield container_id, stop on exit."""
    await ensure_binder_module()
    await pull_image_if_absent()
    container_id = await start_container(container_name)
    try:
        await wait_for_boot(container_id)
        yield container_id
    finally:
        await stop_container(container_id)
