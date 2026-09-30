# SPDX-License-Identifier: MIT
"""P1-0 split-APK bundles: XAPK, APKS, APKM → base + splits."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from engine.ingestion import bundle


def _zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def test_plain_apk_is_used_as_is(tmp_path: Path) -> None:
    apk = _zip(tmp_path / "app.apk", {"AndroidManifest.xml": b"<m/>", "classes.dex": b"dex"})

    assert not bundle.is_bundle(apk)
    assert bundle.apk_set(apk, tmp_path / "out") == [apk]
    assert not (tmp_path / "out").exists()  # nothing unpacked


def test_xapk_base_from_manifest(tmp_path: Path) -> None:
    meta = {
        "package_name": "com.example.pit",
        "split_apks": [
            {"file": "com.example.pit.apk", "id": "base"},
            {"file": "config.en.apk", "id": "config.en"},
        ],
    }
    xapk = _zip(
        tmp_path / "Pit_5.0_APKPure.xapk",
        {
            "manifest.json": json.dumps(meta).encode(),
            "icon.png": b"png",
            "config.en.apk": b"en" * 100,  # bigger than the base: size must not decide
            "com.example.pit.apk": b"base",
            "Android/obb/com.example.pit/main.1.com.example.pit.obb": b"obb",
        },
    )

    apks = bundle.apk_set(xapk, tmp_path / "out")

    assert [p.name for p in apks] == ["com.example.pit.apk", "config.en.apk"]
    assert apks[0].read_bytes() == b"base"
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == [
        "com.example.pit.apk",
        "config.en.apk",
    ]  # no OBB, icon or metadata


def test_apks_base_by_convention(tmp_path: Path) -> None:
    apks_file = _zip(
        tmp_path / "app.apks",
        {"splits/base-master.apk": b"b", "splits/base-arm64_v8a.apk": b"abi" * 50, "toc.pb": b""},
    )

    names = [p.name for p in bundle.apk_set(apks_file, tmp_path / "out")]

    assert names == ["base-master.apk", "base-arm64_v8a.apk"]


def test_base_falls_back_to_largest_apk(tmp_path: Path) -> None:
    b = _zip(tmp_path / "x.apkm", {"a.apk": b"small", "b.apk": b"large" * 100})

    assert bundle.apk_set(b, tmp_path / "out")[0].name == "b.apk"


def test_bundle_detected_by_content_whatever_the_extension(tmp_path: Path) -> None:
    b = _zip(tmp_path / "download.zip", {"base.apk": b"b", "split_config.fr.apk": b"f"})

    assert bundle.is_bundle(b)


def test_member_paths_cannot_escape_dest(tmp_path: Path) -> None:
    b = _zip(tmp_path / "evil.xapk", {"../../escape.apk": b"x", "base.apk": b"b"})
    out = tmp_path / "deep" / "out"

    apks = bundle.apk_set(b, out)

    assert all(p.parent == out for p in apks)
    assert not (tmp_path / "escape.apk").exists()


def test_rejects_empty_and_duplicate_names(tmp_path: Path) -> None:
    empty = _zip(tmp_path / "empty.xapk", {"manifest.json": b"{}"})
    dup = _zip(tmp_path / "dup.apks", {"a/base.apk": b"1", "b/base.apk": b"2"})

    with pytest.raises(bundle.BundleError, match="no APKs"):
        bundle.apk_set(empty, tmp_path / "o1")
    with pytest.raises(bundle.BundleError, match="share a name"):
        bundle.apk_set(dup, tmp_path / "o2")


def test_refuses_oversized_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bundle, "MAX_UNPACKED_BYTES", 10)
    b = _zip(tmp_path / "big.xapk", {"base.apk": b"x" * 100})

    with pytest.raises(bundle.BundleError, match="refusing"):
        bundle.apk_set(b, tmp_path / "out")


def test_encrypted_bundle_explains(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    b = _zip(tmp_path / "enc.apkm", {"base.apk": b"x", "split.apk": b"y"})

    def encrypted(*args: object, **kwargs: object) -> None:
        raise RuntimeError("File <ZipInfo> is encrypted, password required for extraction")

    monkeypatch.setattr(zipfile.ZipFile, "open", encrypted)

    with pytest.raises(bundle.BundleError, match="encrypted"):
        bundle.apk_set(b, tmp_path / "out")


def test_unpacking_again_reuses_files(tmp_path: Path) -> None:
    b = _zip(tmp_path / "a.xapk", {"base.apk": b"b", "config.en.apk": b"e"})
    first = bundle.apk_set(b, tmp_path / "out")
    mtimes = [p.stat().st_mtime_ns for p in first]

    assert bundle.apk_set(b, tmp_path / "out") == first
    assert [p.stat().st_mtime_ns for p in first] == mtimes
