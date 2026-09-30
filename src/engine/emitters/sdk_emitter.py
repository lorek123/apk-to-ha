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
    pkg_dir = out_root / str(ctx["sdk_package"])
    pkg_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )

    _render(env, ctx, pkg_dir, "__init__.py.j2", "__init__.py")
    client = "client_http.py.j2" if ctx.get("transport") == "http_rest" else "client.py.j2"
    _render(env, ctx, pkg_dir, client, "client.py")
    _render(env, ctx, pkg_dir, "models.py.j2", "models.py")
    _render(env, ctx, pkg_dir, "const.py.j2", "const.py")
    if ctx.get("has_udp_discovery"):
        _render(env, ctx, pkg_dir, "discovery.py.j2", "discovery.py")
    _render(env, ctx, out_root, "pyproject.toml.j2", "pyproject.toml")

    # P2-6: emit signing helper + test when a high-confidence trace exists
    if ctx.get("has_signing"):
        _render(env, ctx, pkg_dir, "signing.py.j2", "signing.py")
        tests_dir = out_root / "tests"
        tests_dir.mkdir(exist_ok=True)
        _render(env, ctx, tests_dir, "tests/test_signing.py.j2", "test_signing.py")
        _LOGGER.info(
            "Signing helper emitted (algorithm=%s confidence=%.2f)",
            ctx["signing_algorithm"],
            ctx["signing_confidence"],
        )

    # P4-6: emit Bleak BLE client + test when BLE characteristics were found
    if ctx.get("has_ble"):
        _render(env, ctx, pkg_dir, "ble_client.py.j2", "ble_client.py")
        tests_dir = out_root / "tests"
        tests_dir.mkdir(exist_ok=True)
        _render(env, ctx, tests_dir, "tests/test_ble_client.py.j2", "test_ble_client.py")
        _LOGGER.info("BLE client emitted (%d characteristics)", len(ctx["ble_chars"]))

    # Camera: emit JPEG-over-WebSocket stream client when a streaming contract exists
    if ctx.get("has_camera"):
        _render(env, ctx, pkg_dir, "video_stream.py.j2", "video_stream.py")
        _LOGGER.info("Video stream client emitted (port=%s)", ctx.get("video_port"))

    _LOGGER.info("SDK emitted to %s", pkg_dir)
    return pkg_dir


def _render(
    env: Environment, ctx: dict[str, Any], out_dir: Path, template: str, filename: str
) -> None:
    rendered = env.get_template(template).render(**ctx)
    (out_dir / filename).write_text(rendered)
