# SPDX-License-Identifier: MIT
"""P1-3 — Framework classifier: Native / Flutter / React Native."""
from __future__ import annotations

import logging
from pathlib import Path

from ..ir.models import Framework

_LOGGER = logging.getLogger(__name__)

# Flutter AOT ships these in assets
_FLUTTER_MARKERS = {"flutter_assets", "libflutter.so", "libapp.so"}
# RN bundles JS here
_RN_BUNDLE = "index.android.bundle"
# Tuya / ThingClips SDK packages — P1-2 pre-flight
_TUYA_PACKAGES = {"com.tuya", "com.thingclips", "com.thingclip"}


def classify(apk_out_dir: Path) -> Framework:
    resources = apk_out_dir / "resources"
    sources = apk_out_dir / "sources"

    # Flutter: look for flutter_assets dir or libflutter.so in resources
    if resources.exists():
        for marker in _FLUTTER_MARKERS:
            if any(resources.rglob(marker)):
                _LOGGER.info("Framework: Flutter (found %s)", marker)
                return Framework.FLUTTER

    # React Native: index.android.bundle in assets
    if resources.exists() and any(resources.rglob(_RN_BUNDLE)):
        _LOGGER.info("Framework: React Native (found index.android.bundle)")
        return Framework.REACT_NATIVE

    _LOGGER.info("Framework: Native Java/Kotlin")
    return Framework.NATIVE


def check_tuya(apk_out_dir: Path, package_name: str) -> bool:
    """P1-2 — Return True if Tuya/ThingClips SDK is present (pipeline should halt)."""
    sources = apk_out_dir / "sources"
    # Fast path: check decompiled package directories
    if sources.exists():
        for tuya_pkg in _TUYA_PACKAGES:
            pkg_path = sources / tuya_pkg.replace(".", "/")
            if pkg_path.exists():
                _LOGGER.warning("Tuya SDK detected at %s — use tinytuya instead", pkg_path)
                return True
    # Also check by app package prefix (e.g. com.tuya.smartlife)
    for prefix in _TUYA_PACKAGES:
        if package_name.startswith(prefix):
            _LOGGER.warning("Tuya package name detected: %s", package_name)
            return True
    return False
