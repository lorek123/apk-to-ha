# SPDX-License-Identifier: MIT
"""Tests for first-party vs third-party code detection."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.extraction.app_sources import app_source_files, is_third_party


@pytest.mark.parametrize(
    "name",
    [
        "com.bumptech.glide.load.engine.cache.SafeKeyGenerator",
        "com.koushikdutta.async.http.WebSocketImpl",
        "org.java_websocket.drafts.Draft_10",
        "org.jcodec.common.tools.MD5.md5sumBytes",
        "androidx.core.hardware.fingerprint.FingerprintManagerCompat",
        "okhttp3.internal.ws.WebSocketProtocol",
    ],
)
def test_bundled_libraries_are_third_party(name: str) -> None:
    assert is_third_party(name)


@pytest.mark.parametrize(
    "name",
    ["com.bullb.r2d2.api.RobotApi", "com.example.device.Signer.sign", "javafx_like.App"],
)
def test_app_code_is_first_party(name: str) -> None:
    # "javafx_like" must not match the "java" prefix: matching is per package segment.
    assert not is_third_party(name)


def _touch(root: Path, rel: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("class X {}")
    return path


def test_app_source_files_prefers_app_package(tmp_path: Path) -> None:
    app = _touch(tmp_path, "com/example/device/Api.java")
    _touch(tmp_path, "com/example/other/Util.java")

    assert app_source_files(tmp_path, "com.example.device") == [app]


def test_app_source_files_falls_back_to_first_party(tmp_path: Path) -> None:
    app = _touch(tmp_path, "com/vendor/app/Api.java")
    _touch(tmp_path, "com/bumptech/glide/Glide.java")
    _touch(tmp_path, "okhttp3/Call.java")

    assert app_source_files(tmp_path, "com.example.missing") == [app]


def test_app_source_files_follows_manifest_entry_points_and_modules(tmp_path: Path) -> None:
    """KMP apps: the package folder is only R.java; code sits in the entry points' packages
    and in bare module packages (data/, domain/) imported from them."""
    sources = tmp_path / "sources"
    _touch(sources, "dev/app/aos/R.java")
    main = _touch(sources, "dev/vendor/p007io/MainActivity.java")
    main.write_text("package dev.vendor.p007io;\nimport data.network.Api;\nclass MainActivity {}")
    api = _touch(sources, "data/network/Api.java")
    api.write_text("package data.network;\nimport domain.Model;\nclass Api {}")
    model = _touch(sources, "domain/Model.java")
    _touch(sources, "unused/Thing.java")  # not imported: not app code
    _touch(sources, "p001a/Obf.java")  # obfuscated: never a module
    manifest = tmp_path / "resources" / "AndroidManifest.xml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        '<manifest package="dev.app.aos"><application>'
        '<activity android:name="dev.vendor.p007io.MainActivity"><intent-filter>'
        '<action android:name="android.intent.action.MAIN"/>'
        '<category android:name="android.intent.category.LAUNCHER"/>'
        "</intent-filter></activity></application></manifest>"
    )

    files = set(app_source_files(sources, "dev.app.aos"))

    assert {main, api, model} <= files
    assert not any(f.parts[-2] in ("unused", "p001a") for f in files)


def test_vendor_sibling_packages_imported_by_the_app_are_app_code(tmp_path: Path) -> None:
    """JBL Portable (com.harman.ble.jbllink) keeps its speaker protocol in com.harman.sdk."""
    sources = tmp_path / "sources"
    app = _touch(sources, "com/harman/ble/jbllink/App.java")
    app.write_text(
        "package com.harman.ble.jbllink;\nimport com.harman.sdk.DeviceMgr;\nclass App {}"
    )
    mgr = _touch(sources, "com/harman/sdk/DeviceMgr.java")
    mgr.write_text(
        "package com.harman.sdk;\nimport com.harman.sdk.command.ReqBattery;\nclass DeviceMgr {}"
    )
    cmd = _touch(sources, "com/harman/sdk/command/ReqBattery.java")
    _touch(sources, "com/harman/unused/Thing.java")  # same vendor, never imported
    _touch(sources, "com/harman/ab/Obf.java")  # R8 bucket in the vendor namespace
    _touch(sources, "com/other/sdk/Lib.java")  # another vendor

    files = set(app_source_files(sources, "com.harman.ble.jbllink"))

    assert {app, mgr, cmd} <= files
    assert not any(p in str(f) for f in files for p in ("unused", "/ab/", "com/other"))


def test_hosting_namespaces_scope_the_vendor_to_the_owner(tmp_path: Path) -> None:
    """io.github.alice.app must not pull in io.github.bob (another owner)."""
    sources = tmp_path / "sources"
    app = _touch(sources, "io/github/alice/app/App.java")
    app.write_text(
        "package io.github.alice.app;\n"
        "import io.github.alice.core.Api;\nimport io.github.bob.lib.Util;\nclass App {}"
    )
    api = _touch(sources, "io/github/alice/core/Api.java")
    _touch(sources, "io/github/bob/lib/Util.java")

    files = set(app_source_files(sources, "io.github.alice.app"))

    assert api in files
    assert not any("bob" in str(f) for f in files)
