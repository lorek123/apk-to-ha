# SPDX-License-Identifier: MIT
"""P4 — SDK emitter: renders the standalone pip-installable SDK package."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

_LOGGER = logging.getLogger(__name__)
_TEMPLATES_DIR = Path(__file__).parents[1] / "templates" / "sdk"


def emit(ctx: dict[str, Any], out_root: Path) -> Path:
    """Render the SDK package into *out_root*/{sdk_package}/. Returns that dir."""
    pkg_dir = out_root / ctx["sdk_package"]
    pkg_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )

    _render(env, ctx, pkg_dir, "__init__.py.j2", "__init__.py")
    _render(env, ctx, pkg_dir, "client.py.j2", "client.py")
    _render(env, ctx, pkg_dir, "models.py.j2", "models.py")
    _render(env, ctx, pkg_dir, "const.py.j2", "const.py")
    _render(env, ctx, pkg_dir, "discovery.py.j2", "discovery.py")
    _render(env, ctx, out_root, "pyproject.toml.j2", "pyproject.toml")

    _LOGGER.info("SDK emitted to %s", pkg_dir)
    return pkg_dir


def _render(env: Environment, ctx: dict, out_dir: Path, template: str, filename: str) -> None:
    rendered = env.get_template(template).render(**ctx)
    (out_dir / filename).write_text(rendered)
