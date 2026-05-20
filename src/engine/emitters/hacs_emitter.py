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


def emit(ctx: dict[str, Any], out_root: Path) -> Path:
    """Render HACS integration into *out_root*/custom_components/{domain}/."""
    domain_dir = out_root / "custom_components" / ctx["domain"]
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


def _render(env: Environment, ctx: dict, out_dir: Path, template: str, filename: str) -> None:
    rendered = env.get_template(template).render(**ctx)
    (out_dir / filename).write_text(rendered)
