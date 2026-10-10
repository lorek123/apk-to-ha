# SPDX-License-Identifier: MIT
"""First-party vs third-party code in a decompiled APK.

Protocol, crypto and signing analysis should only look at the app's own code.
Bundled libraries (image loaders, WebSocket stacks, codecs) use crypto for
their own purposes — Glide's cache-key SHA-256 is not a device protocol — and
drown the real signal while wasting LLM escalations.
"""

from __future__ import annotations

import re
from pathlib import Path

# Dotted package prefixes of libraries commonly bundled in device-companion apps.
_MIN_MODULE_NAME = 4
_APPLICATION = re.compile(r'<application\b[^>]*?android:name="([A-Za-z_][\w.$]*)"')
_ACTIVITY_BLOCK = re.compile(r"<activity\b[\s\S]*?</activity>")
_NAME_ATTR = re.compile(r'android:name="([A-Za-z_][\w.$]*)"')
_IMPORT_FQN = re.compile(r"^import\s+(?:static\s+)?([\w.]+)\.[\w*]+\s*;", re.MULTILINE)
# Inside the vendor's namespace (and imported by app code) a 3-letter name is a real
# package (com.harman.sdk); R8 buckets there are 1-2 letters or pNNN.
_OBFUSCATED_VENDOR = re.compile(r"p\d+|[a-z]{1,2}\d*")
# Second package segments that host many owners: the vendor is one level deeper.
_HOSTING_NAMESPACES = frozenset({"github", "gitlab", "sourceforge", "bitbucket", "codeberg"})
_OBFUSCATED = re.compile(r"p\d+|[a-z]{1,3}\d*")

THIRD_PARTY_PACKAGES: tuple[str, ...] = (
    "_COROUTINE",
    "android",
    "androidx",
    "app.cash",
    "co.touchlab",
    "coil",
    "coil3",
    "com.android",
    "com.bumptech.glide",
    "com.facebook",
    "com.fasterxml.jackson",
    "com.google",
    "com.koushikdutta",
    "com.russhwolf",
    "com.squareup",
    "commons",
    "dagger",
    "io.ktor",
    "io.reactivex",
    "io.sentry",
    "java",
    "javax",
    "kotlin",
    "kotlinx",
    "okhttp3",
    "okio",
    "org.apache",
    "org.greenrobot",
    "org.java_websocket",
    "org.jcodec",
    "org.jetbrains",
    "org.json",
    "org.koin",
    "org.kotlincrypto",
    "org.orbitmvi",
    "org.slf4j",
    "retrofit2",
)


def is_third_party(qualified_name: str) -> bool:
    """True if *qualified_name* (a class or method) lives in a known library package."""
    return any(
        qualified_name == pkg or qualified_name.startswith(pkg + ".")
        for pkg in THIRD_PARTY_PACKAGES
    )


def module_packages(sources_dir: Path, app_package: str) -> list[Path]:
    """The app's own module packages outside its package folder.

    Two kinds, each counted only if the app's code imports it (followed
    transitively):

    - bare top-level packages (data, domain, presentation) of multi-module and
      Kotlin Multiplatform apps. Bare names can also be repackaged libraries
      (commons.validator), and R8's obfuscation buckets (p000, a, bc) mix in
      library code, hence the import requirement.
    - sibling packages in the vendor's namespace: com.harman.ble.jbllink keeps
      its speaker protocol in com.harman.sdk.
    """
    app_root = app_package.split(".", 1)[0]
    bare = {
        d.name: d
        for d in sources_dir.iterdir()
        if d.is_dir()
        and d.name != app_root
        and len(d.name) >= _MIN_MODULE_NAME
        and not _OBFUSCATED.fullmatch(d.name)
        and not is_third_party(d.name)
    }
    vendor = _vendor_prefix(app_package)
    roots = _code_roots(sources_dir, app_package)

    def module_of(fqn: str) -> Path | None:
        parts = fqn.split(".")
        if parts[0] in bare:
            return bare[parts[0]]
        if parts[: len(vendor)] != vendor or len(parts) <= len(vendor):
            return None
        name = parts[: len(vendor) + 1]
        d = sources_dir.joinpath(*name)
        if (
            not d.is_dir()
            or is_third_party(".".join(name))
            or _OBFUSCATED_VENDOR.fullmatch(name[-1])
            or any(r == d or r.is_relative_to(d) or d.is_relative_to(r) for r in roots)
        ):
            return None
        return d

    frontier = [f for d in roots for f in d.rglob("*.java")]
    included: dict[Path, None] = {}
    while frontier:
        imported = {m for f in frontier for m in _IMPORT_FQN.findall(f.read_text(errors="replace"))}
        new = [
            d
            for d in dict.fromkeys(module_of(m) for m in sorted(imported))
            if d is not None and d not in included
        ]
        included.update(dict.fromkeys(new))
        frontier = [f for d in new for f in d.rglob("*.java")]
    return list(included)


def _vendor_prefix(app_package: str) -> list[str]:
    """com.harman.ble.jbllink → [com, harman]; io.github.user.app → [io, github, user]."""
    parts = app_package.split(".")
    size = 3 if len(parts) > 3 and parts[1] in _HOSTING_NAMESPACES else 2
    return parts[:size]


def _entry_points(sources_dir: Path) -> list[str]:
    """The application class and the launcher activity — the app's own entry points.

    Other components in a merged manifest may come from libraries (FileKit,
    Dexter declare activities), so they don't mark app code.
    """
    manifest = sources_dir.parent / "resources" / "AndroidManifest.xml"
    if not manifest.exists():
        return []
    text = manifest.read_text(errors="replace")
    names = _APPLICATION.findall(text)
    for activity in _ACTIVITY_BLOCK.finditer(text):
        if "android.intent.category.LAUNCHER" in activity.group(0):
            names += _NAME_ATTR.findall(activity.group(0))[:1]
    return [n for n in names if not is_third_party(n)]


def _code_roots(sources_dir: Path, app_package: str) -> list[Path]:
    """The app package folder plus the packages holding the manifest's components.

    The declared package often isn't where the code lives (dev.inkcast.aos has
    only R; the application and activities are in dev.yaxca.io).
    """
    roots: dict[Path, None] = {}
    pkg_path = sources_dir / app_package.replace(".", "/")
    if pkg_path.exists():
        roots[pkg_path] = None
    for name in _entry_points(sources_dir):
        f = sources_dir / (name.replace(".", "/") + ".java")
        if f.exists() and f.parent != sources_dir:
            roots[f.parent] = None
    # Drop roots nested inside another root.
    return [r for r in roots if not any(o != r and r.is_relative_to(o) for o in roots)]


def app_source_files(sources_dir: Path, app_package: str) -> list[Path]:
    """Java files to scan: the app's code roots (package folder, manifest components)
    and the bare module packages they import; else all first-party files."""
    roots = _code_roots(sources_dir, app_package)
    if roots:
        files = [f for r in roots for f in r.rglob("*.java")]
        for module in module_packages(sources_dir, app_package):
            files += module.rglob("*.java")
        return list(dict.fromkeys(files))
    return [
        f
        for f in sources_dir.rglob("*.java")
        if not is_third_party(".".join(f.relative_to(sources_dir).with_suffix("").parts))
    ]
