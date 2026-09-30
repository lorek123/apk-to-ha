# SPDX-License-Identifier: MIT
"""P1-0 — Split-APK bundles: XAPK (APKPure), APKS (bundletool/SAI), APKM (APKMirror).

Store downloads often come as a bundle: a zip of the base APK plus split APKs
(language, density, ABI, dynamic features). The code is in the base and any
feature split with a classes.dex; language splits carry the translated strings.

``apk_set(path, dest)`` returns the APKs to analyse, base first:

  - a plain APK → [path] (nothing unpacked)
  - a bundle   → its APKs, unpacked into *dest*

jadx given several inputs merges them into one tree (code plus resources with
every split's values-xx), and ``adb install-multiple`` installs the same set.
Only ``*.apk`` members are extracted, by base name (no zip-slip), and OBB
expansion files are skipped.
"""

from __future__ import annotations

import json
import logging
import zipfile
from pathlib import Path, PurePosixPath

_LOGGER = logging.getLogger(__name__)

BUNDLE_SUFFIXES = frozenset({".xapk", ".apks", ".apkm"})
# A bundle's APKs together: generous, but stops a zip bomb before it fills the disk.
MAX_UNPACKED_BYTES = 4 * 1024**3
_BASE_NAMES = ("base.apk", "base-master.apk")


class BundleError(Exception):
    """The file is a bundle we can't unpack (encrypted, empty, or malformed)."""


def is_bundle(path: Path) -> bool:
    """A zip of APKs rather than an APK (whatever its extension says)."""
    if path.suffix.lower() in BUNDLE_SUFFIXES:
        return True
    if not zipfile.is_zipfile(path):
        return False
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
    return "AndroidManifest.xml" not in names and any(n.endswith(".apk") for n in names)


def apk_set(path: Path, dest: Path) -> list[Path]:
    """The APKs to analyse and install, base first."""
    if not is_bundle(path):
        return [path]
    try:
        with zipfile.ZipFile(path) as zf:
            return _unpack(zf, dest)
    except zipfile.BadZipFile as exc:
        raise BundleError(f"{path.name} is not a valid bundle: {exc}") from exc
    except RuntimeError as exc:  # zipfile: "File … is encrypted, password required"
        raise BundleError(
            f"{path.name} is encrypted (newer APKMirror .apkm files are); "
            "export the APKs with the store's installer and pass the base APK"
        ) from exc


def _unpack(zf: zipfile.ZipFile, dest: Path) -> list[Path]:
    members = [
        info
        for info in zf.infolist()
        if info.filename.endswith(".apk")
        and not info.is_dir()
        and not PurePosixPath(info.filename).parts[0].lower() == "android"  # Android/obb/…
    ]
    if not members:
        raise BundleError("no APKs inside")
    total = sum(info.file_size for info in members)
    if total > MAX_UNPACKED_BYTES:
        raise BundleError(f"unpacks to {total / 1024**3:.1f} GiB; refusing")
    names = [PurePosixPath(info.filename).name for info in members]
    if len(set(names)) != len(names):
        raise BundleError("two APKs share a name")

    base = _base_name(zf, names)
    dest.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for info, name in zip(members, names, strict=True):
        target = dest / name  # base name only: nothing can land outside dest
        if not (target.exists() and target.stat().st_size == info.file_size):
            with zf.open(info) as src, target.open("wb") as out:
                while chunk := src.read(1 << 20):
                    out.write(chunk)
        paths.append(target)
    paths.sort(key=lambda p: (p.name != base, p.name))
    _LOGGER.info("bundle: base %s + %d split(s)", base, len(paths) - 1)
    return paths


def _base_name(zf: zipfile.ZipFile, names: list[str]) -> str:
    """Which APK is the base: the bundle's own metadata, else convention, else size."""
    if "manifest.json" in zf.namelist():  # XAPK
        try:
            meta = json.loads(zf.read("manifest.json"))
        except json.JSONDecodeError, UnicodeDecodeError:
            meta = {}
        for split in meta.get("split_apks") or []:
            if split.get("id") == "base" and split.get("file") in names:
                return str(split["file"])
        package = meta.get("package_name")
        if package and f"{package}.apk" in names:
            return f"{package}.apk"
    for candidate in _BASE_NAMES:
        if candidate in names:
            return candidate
    if len(names) == 1:
        return names[0]
    # Last resort: the biggest APK (the base carries the code).
    sizes = {PurePosixPath(i.filename).name: i.file_size for i in zf.infolist()}
    return max(names, key=lambda n: sizes.get(n, 0))
