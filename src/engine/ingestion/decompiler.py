# SPDX-License-Identifier: MIT
"""JADX CLI wrapper — decompiles an APK to a source tree."""
from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

JADX_TIMEOUT = 300  # seconds; large APKs can take a while


async def decompile(apk_path: Path, out_dir: Path) -> Path:
    """Run jadx CLI, return the output directory.

    Idempotent: skips decompilation if out_dir already contains sources/.
    """
    sources = out_dir / "sources"
    if sources.exists() and any(sources.rglob("*.java")):
        _LOGGER.debug("Skipping decompilation, %s already populated", out_dir)
        return out_dir

    jadx = shutil.which("jadx")
    if not jadx:
        raise FileNotFoundError("jadx not found on PATH — run scripts/setup.sh first")

    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        jadx,
        "--deobf",
        "--show-bad-code",
        "-d", str(out_dir),
        str(apk_path),
    ]
    _LOGGER.info("Decompiling %s → %s", apk_path.name, out_dir)
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=JADX_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"jadx timed out after {JADX_TIMEOUT}s on {apk_path.name}")

    # JADX exit codes: 0=clean, 1=partial errors, 2=bad args, 3+=severe but may still produce output.
    # Trust the output directory rather than the exit code.
    java_files = list((out_dir / "sources").rglob("*.java")) if (out_dir / "sources").exists() else []
    if not java_files:
        raise RuntimeError(f"jadx produced no Java files (rc={proc.returncode}): {stderr.decode()[:500]}")

    error_lines = [ln for ln in stderr.decode().splitlines() if "ERROR" in ln]
    if error_lines:
        _LOGGER.debug("jadx reported %d errors (normal for release APKs)", len(error_lines))

    return out_dir
