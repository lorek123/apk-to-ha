# SPDX-License-Identifier: MIT
from __future__ import annotations

from pathlib import Path
from typing import Any

from engine.emitters import context, hacs_emitter, sdk_emitter

__all__ = ["context", "emit_all", "hacs_emitter", "sdk_emitter"]


def emit_all(ctx: dict[str, Any], out_root: Path) -> tuple[Path, Path, Path | None]:
    """SDK, HACS integration and its runtime tests: (sdk_dir, hacs_dir, tests_dir)."""
    return (
        sdk_emitter.emit(ctx, out_root),
        hacs_emitter.emit(ctx, out_root),
        hacs_emitter.emit_tests(ctx, out_root),
    )
