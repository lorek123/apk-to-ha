# SPDX-License-Identifier: MIT
"""Async ADB wrapper for the redroid container."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

# frida-server binary shipped inside this package for x86_64 Android 13
_FRIDA_SERVER_VERSION = "17.9.10"
_FRIDA_SERVER_REMOTE = "/data/local/tmp/frida-server"
_FRIDA_SERVER_URL = (
    f"https://github.com/frida/frida/releases/download/{_FRIDA_SERVER_VERSION}/"
    f"frida-server-{_FRIDA_SERVER_VERSION}-android-x86_64.xz"
)
_FRIDA_SERVER_LOCAL = Path(__file__).parents[3] / ".cache" / "frida-server"


async def _run(args: list[str], check: bool = True) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    rc = proc.returncode or 0
    if check and rc != 0:
        raise RuntimeError(f"Command failed (rc={rc}): {' '.join(args)}\n{stderr.decode()}")
    return rc, stdout.decode(), stderr.decode()


async def adb(*args: str, check: bool = True) -> tuple[int, str, str]:
    """Run an adb command against the redroid container (localhost:5555)."""
    return await _run(["adb", "-s", "localhost:5555", *args], check=check)


async def connect() -> None:
    """Connect adb to the redroid container."""
    rc, out, _ = await _run(["adb", "connect", "localhost:5555"], check=False)
    _LOGGER.debug("adb connect: %s", out.strip())
    # Wait for device to be ready
    await adb("wait-for-device")
    _LOGGER.info("adb: device ready")


async def install_apk(apk_path: Path) -> None:
    _LOGGER.info("adb: installing %s", apk_path.name)
    await adb("install", "-r", "-t", str(apk_path))


async def ensure_frida_server() -> None:
    """Download (if needed) and push frida-server to the device."""
    if not _FRIDA_SERVER_LOCAL.exists():
        _LOGGER.info("adb: downloading frida-server %s", _FRIDA_SERVER_VERSION)
        _FRIDA_SERVER_LOCAL.parent.mkdir(parents=True, exist_ok=True)
        import urllib.request
        import lzma
        xz_path = Path(str(_FRIDA_SERVER_LOCAL) + ".xz")
        urllib.request.urlretrieve(_FRIDA_SERVER_URL, xz_path)  # noqa: S310
        with lzma.open(xz_path) as f_in, _FRIDA_SERVER_LOCAL.open("wb") as f_out:
            f_out.write(f_in.read())
        xz_path.unlink()
        _LOGGER.info("adb: frida-server downloaded")

    _LOGGER.debug("adb: pushing frida-server")
    await adb("push", str(_FRIDA_SERVER_LOCAL), _FRIDA_SERVER_REMOTE)
    await adb("shell", "chmod", "755", _FRIDA_SERVER_REMOTE)


async def start_frida_server() -> None:
    """Start frida-server in the background (non-blocking shell)."""
    # Kill any existing instance first
    await adb("shell", "pkill", "-f", "frida-server", check=False)
    await asyncio.sleep(0.5)
    # Start in background via nohup
    await adb("shell", f"nohup {_FRIDA_SERVER_REMOTE} &>/dev/null &")
    await asyncio.sleep(1.0)
    _LOGGER.info("adb: frida-server started")


async def get_package_name_from_apk(apk_path: Path) -> str | None:
    """Extract package name from APK using aapt (if available) or manifest."""
    rc, out, _ = await _run(
        ["aapt", "dump", "badging", str(apk_path)], check=False
    )
    if rc == 0:
        for line in out.splitlines():
            if line.startswith("package:"):
                for part in line.split():
                    if part.startswith("name="):
                        return part.split("=", 1)[1].strip("'\"")
    return None


async def launch_app(package_name: str) -> None:
    """Start the app's main activity via Android intent."""
    _LOGGER.info("adb: launching %s", package_name)
    await adb(
        "shell", "monkey", "-p", package_name,
        "-c", "android.intent.category.LAUNCHER", "1",
    )
