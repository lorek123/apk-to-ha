# SPDX-License-Identifier: MIT
"""Sandbox health checks — verifies the Docker image is correctly configured.

These run inside the container via `docker run hacs-engine-sandbox pytest`.
"""
from __future__ import annotations

import subprocess


def test_ha_core_importable() -> None:
    import homeassistant.core  # noqa: F401


def test_ha_loader_importable() -> None:
    import homeassistant.loader  # noqa: F401


def test_ruff_on_path() -> None:
    r = subprocess.run(["ruff", "--version"], capture_output=True, text=True)
    assert r.returncode == 0, f"ruff not on PATH: {r.stderr}"


def test_mypy_on_path() -> None:
    r = subprocess.run(["mypy", "--version"], capture_output=True, text=True)
    assert r.returncode == 0, f"mypy not on PATH: {r.stderr}"
