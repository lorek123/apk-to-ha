# SPDX-License-Identifier: MIT
"""P5 — HACS integration emitter: renders the custom_components package."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

_LOGGER = logging.getLogger(__name__)
_TEMPLATES_DIR = Path(__file__).parents[1] / "templates" / "hacs"
_TESTS_TEMPLATES_DIR = Path(__file__).parents[1] / "templates" / "hacs_tests"


def emit_tests(ctx: dict[str, Any], out_root: Path) -> Path | None:
    """Render runtime tests into *out_root*/tests/ (run by V-3 in the sandbox).

    Returns the tests dir, or None when the integration has no push-state entity
    to probe or uses a transport the mock device can't speak (BLE).
    """
    probe = _test_probe(ctx)
    if probe is None or ctx.get("has_ble"):
        _LOGGER.info("No runtime tests emitted for %s (no probe entity or BLE)", ctx["domain"])
        return None

    env = Environment(
        loader=FileSystemLoader(str(_TESTS_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    tests_ctx = {
        **ctx,
        "test_probe": probe,
        "test_initial_state": {probe["key"]: probe["initial_value"]},
    }
    tests_dir = out_root / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    _render(env, tests_ctx, out_root, "pytest.ini.j2", "pytest.ini")
    for name in ("__init__.py", "conftest.py", "test_integration.py"):
        _render(env, tests_ctx, tests_dir, f"{name}.j2", name)
    _fix_imports(tests_dir)
    return tests_dir


def _test_probe(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Pick one state-backed entity whose value the runtime tests drive and observe."""
    if ctx.get("sensors"):
        spec = ctx["sensors"][0]
        return {
            "platform": "sensor",
            "key": spec["key"],
            "initial_value": 1,
            "initial_state": "1",
            "next_value": 2,
            "next_state": "2",
        }
    if ctx.get("binary_sensors"):
        spec = ctx["binary_sensors"][0]
        return {
            "platform": "binary_sensor",
            "key": spec["key"],
            "initial_value": True,
            "initial_state": "on",
            "next_value": False,
            "next_state": "off",
        }
    return None


def emit(ctx: dict[str, Any], out_root: Path) -> Path:
    """Render HACS integration into *out_root*/custom_components/{domain}/."""
    domain_dir = out_root / "custom_components" / str(ctx["domain"])
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / "translations").mkdir(exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )

    _render(env, ctx, domain_dir, "manifest.json.j2", "manifest.json")
    _render(env, ctx, domain_dir, "__init__.py.j2", "__init__.py")
    _render(env, ctx, domain_dir, "const.py.j2", "const.py")
    _render(env, ctx, domain_dir, "config_flow.py.j2", "config_flow.py")
    _render(env, ctx, domain_dir, "coordinator.py.j2", "coordinator.py")
    if ctx.get("has_ble"):
        _render(env, ctx, domain_dir, "ble_coordinator.py.j2", "ble_coordinator.py")
    _render(env, ctx, domain_dir, "entity_base.py.j2", "entity_base.py")
    _render(env, ctx, domain_dir, "strings.json.j2", "strings.json")
    _render(env, ctx, domain_dir / "translations", "translations/en.json.j2", "en.json")

    platforms = ctx["platforms"]
    if "sensor" in platforms:
        _render(env, ctx, domain_dir, "sensor.py.j2", "sensor.py")
    if "binary_sensor" in platforms:
        _render(env, ctx, domain_dir, "binary_sensor.py.j2", "binary_sensor.py")
    if "switch" in platforms:
        _render(env, ctx, domain_dir, "switch.py.j2", "switch.py")
    if "button" in platforms:
        _render(env, ctx, domain_dir, "button.py.j2", "button.py")
    if "select" in platforms:
        _render(env, ctx, domain_dir, "select.py.j2", "select.py")
    if "number" in platforms:
        _render(env, ctx, domain_dir, "number.py.j2", "number.py")
    if ctx.get("has_camera"):
        _render(env, ctx, domain_dir, "camera.py.j2", "camera.py")

    _fix_imports(domain_dir)
    _LOGGER.info("HACS integration emitted to %s", domain_dir)
    return domain_dir


def _fix_imports(directory: Path) -> None:
    """Run ruff --fix to sort imports in emitted Python files."""
    try:
        subprocess.run(
            ["ruff", "check", "--select", "I001", "--fix", str(directory)],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        _LOGGER.debug("ruff not found; skipping import sort")


def _render(
    env: Environment, ctx: dict[str, Any], out_dir: Path, template: str, filename: str
) -> None:
    rendered = env.get_template(template).render(**ctx)
    (out_dir / filename).write_text(rendered)
