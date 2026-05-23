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

# Import prefixes that survive package obfuscation in JADX output
_TUYA_IMPORT_PREFIXES = tuple(f"import {p}." for p in _TUYA_PACKAGES)

# Manifest component name substrings (often unobfuscated even in whitelabels)
_TUYA_MANIFEST_MARKERS = {"tuya", "thingclips", "thingclip"}

# Tuya cloud API hostnames hardcoded in constants / string resources
_TUYA_API_HOSTS = {
    "openapi.tuyacn.com",
    "openapi.tuyaeu.com",
    "openapi.tuyaus.com",
    "openapi-ueaz.tuyaus.com",
    "openapi-weaz.tuyaeu.com",
    "tuyacloud.com",
}

# Bytes read from each Java file when scanning imports (imports are always near the top)
_IMPORT_SCAN_BYTES = 4096


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
    """P1-2 — Return True if Tuya/ThingClips SDK is present (pipeline should halt).

    Detection runs four passes in cheapest-first order, stopping as soon as any
    one fires.  This covers both first-party apps and whitelabels — including
    obfuscated ones where the package directory is renamed but Tuya signals still
    survive in the manifest, import statements, or string constants.

    Passes:
      1. Source package directory presence (fast, unobfuscated SDK)
      2. App package-name prefix
      3. AndroidManifest.xml text scan (service/receiver names survive obfuscation)
      4. Java import statements in source files (JADX reconstructs these even when
         package dirs are renamed; reads only the first 4 KB per file)
      5. Tuya cloud API hostname strings in source + resource files
    """
    sources = apk_out_dir / "sources"

    # Pass 1 — package directory (fast path, unobfuscated)
    if sources.exists():
        for tuya_pkg in _TUYA_PACKAGES:
            pkg_path = sources / tuya_pkg.replace(".", "/")
            if pkg_path.exists():
                _LOGGER.warning("Tuya SDK detected (package dir %s) — use tinytuya instead", pkg_path)
                return True

    # Pass 2 — app package name prefix
    for prefix in _TUYA_PACKAGES:
        if package_name.startswith(prefix):
            _LOGGER.warning("Tuya app package name detected: %s", package_name)
            return True

    # Pass 3 — AndroidManifest.xml text (component names often not obfuscated)
    if _tuya_in_manifest(apk_out_dir):
        return True

    # Pass 4 — Java import statements (survives package-dir obfuscation)
    if sources.exists() and _tuya_in_imports(sources):
        return True

    # Pass 5 — Tuya cloud API hostname strings
    if _tuya_in_api_strings(apk_out_dir):
        return True

    return False


def _tuya_in_manifest(apk_out_dir: Path) -> bool:
    manifest = apk_out_dir / "resources" / "AndroidManifest.xml"
    if not manifest.exists():
        return False
    try:
        text = manifest.read_text(errors="replace").lower()
    except OSError:
        return False
    for marker in _TUYA_MANIFEST_MARKERS:
        if marker in text:
            _LOGGER.warning("Tuya SDK detected in AndroidManifest.xml (marker '%s')", marker)
            return True
    return False


def _tuya_in_imports(sources: Path) -> bool:
    """Scan the first _IMPORT_SCAN_BYTES of each Java file for Tuya import lines."""
    for java_file in sources.rglob("*.java"):
        try:
            with java_file.open("rb") as fh:
                head = fh.read(_IMPORT_SCAN_BYTES).decode(errors="replace")
        except OSError:
            continue
        for line in head.splitlines():
            stripped = line.strip()
            if any(stripped.startswith(prefix) for prefix in _TUYA_IMPORT_PREFIXES):
                _LOGGER.warning(
                    "Tuya SDK detected (import in %s: %s)", java_file.name, stripped[:80]
                )
                return True
    return False


def _tuya_in_api_strings(apk_out_dir: Path) -> bool:
    """Scan source files and XML resources for Tuya cloud API hostnames."""
    candidates: list[Path] = []
    sources = apk_out_dir / "sources"
    resources = apk_out_dir / "resources"
    if sources.exists():
        candidates.extend(sources.rglob("*.java"))
    if resources.exists():
        candidates.extend(resources.rglob("*.xml"))
    for f in candidates:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for host in _TUYA_API_HOSTS:
            if host in text:
                _LOGGER.warning(
                    "Tuya SDK detected (API host '%s' in %s)", host, f.name
                )
                return True
    return False
