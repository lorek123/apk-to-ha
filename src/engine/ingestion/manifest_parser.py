# SPDX-License-Identifier: MIT
"""P1-4 — AndroidManifest.xml parser."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree as ET

_LOGGER = logging.getLogger(__name__)

_ANDROID_NS = "http://schemas.android.com/apk/res/android"


@dataclass
class ManifestInfo:
    package_name: str
    version_name: str | None
    version_code: str | None
    min_sdk: int | None
    target_sdk: int | None
    permissions: list[str]
    activities: list[str]
    services: list[str]
    receivers: list[str]
    providers: list[str]
    has_nsd_manager: bool       # NsdManager → zeroconf/mDNS discovery
    has_bluetooth: bool
    has_wifi: bool
    has_internet: bool
    application_class: str | None
    launcher_activity: str | None
    meta_data: dict[str, str] = field(default_factory=dict)


def parse(apk_out_dir: Path) -> ManifestInfo:
    manifest_path = apk_out_dir / "resources" / "AndroidManifest.xml"
    if not manifest_path.exists():
        raise FileNotFoundError(f"AndroidManifest.xml not found at {manifest_path}")

    tree = ET.parse(manifest_path)
    root = tree.getroot()

    def a(name: str) -> str:
        return f"{{{_ANDROID_NS}}}{name}"

    package = root.get("package", "")
    version_name = root.get(a("versionName"))
    version_code = root.get(a("versionCode"))

    sdk = root.find("uses-sdk")
    min_sdk = int(sdk.get(a("minSdkVersion"), "0")) if sdk is not None else None
    target_sdk = int(sdk.get(a("targetSdkVersion"), "0")) if sdk is not None else None

    permissions = [
        el.get(a("name"), "")
        for el in root.findall("uses-permission")
    ]

    app = root.find("application")
    application_class = app.get(a("name")) if app is not None else None
    activities = [el.get(a("name"), "") for el in (app or []).findall("activity")]
    services = [el.get(a("name"), "") for el in (app or []).findall("service")]
    receivers = [el.get(a("name"), "") for el in (app or []).findall("receiver")]
    providers = [el.get(a("name"), "") for el in (app or []).findall("provider")]

    launcher_activity: str | None = None
    for act in (app or []).findall("activity"):
        for intent in act.findall("intent-filter"):
            actions = [ac.get(a("name"), "") for ac in intent.findall("action")]
            if "android.intent.action.MAIN" in actions:
                launcher_activity = act.get(a("name"))
                break

    meta_data = {
        el.get(a("name"), ""): el.get(a("value"), "")
        for el in (app or []).findall("meta-data")
    }

    perm_set = set(permissions)
    return ManifestInfo(
        package_name=package,
        version_name=version_name,
        version_code=version_code,
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=permissions,
        activities=activities,
        services=services,
        receivers=receivers,
        providers=providers,
        has_nsd_manager=_source_references_nsd(apk_out_dir),
        has_bluetooth=any("BLUETOOTH" in p for p in perm_set),
        has_wifi=any("WIFI" in p for p in perm_set),
        has_internet="android.permission.INTERNET" in perm_set,
        application_class=application_class,
        launcher_activity=launcher_activity,
        meta_data=meta_data,
    )


def _source_references_nsd(apk_out_dir: Path) -> bool:
    """Cheap check: does any source file import NsdManager?"""
    sources = apk_out_dir / "sources"
    if not sources.exists():
        return False
    for java_file in sources.rglob("*.java"):
        try:
            if "NsdManager" in java_file.read_text(errors="replace"):
                return True
        except OSError:
            pass
    return False
