# SPDX-License-Identifier: MIT
"""First-party vs third-party code in a decompiled APK.

Protocol, crypto and signing analysis should only look at the app's own code.
Bundled libraries (image loaders, WebSocket stacks, codecs) use crypto for
their own purposes — Glide's cache-key SHA-256 is not a device protocol — and
drown the real signal while wasting LLM escalations.
"""

from __future__ import annotations

from pathlib import Path

# Dotted package prefixes of libraries commonly bundled in device-companion apps.
THIRD_PARTY_PACKAGES: tuple[str, ...] = (
    "android",
    "androidx",
    "com.android",
    "com.bumptech.glide",
    "com.facebook",
    "com.fasterxml.jackson",
    "com.google",
    "com.koushikdutta",
    "com.squareup",
    "dagger",
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
    "org.json",
    "org.slf4j",
    "retrofit2",
)


def is_third_party(qualified_name: str) -> bool:
    """True if *qualified_name* (a class or method) lives in a known library package."""
    return any(
        qualified_name == pkg or qualified_name.startswith(pkg + ".")
        for pkg in THIRD_PARTY_PACKAGES
    )


def app_source_files(sources_dir: Path, app_package: str) -> list[Path]:
    """Java files to scan: the app package's tree if present, else all first-party files."""
    pkg_path = sources_dir / app_package.replace(".", "/")
    if pkg_path.exists():
        return list(pkg_path.rglob("*.java"))
    return [
        f
        for f in sources_dir.rglob("*.java")
        if not is_third_party(".".join(f.relative_to(sources_dir).with_suffix("").parts))
    ]
