# SPDX-License-Identifier: MIT
"""Tests for resolving the app's display name from AndroidManifest.xml."""

from __future__ import annotations

from pathlib import Path

import pytest

from engine.ingestion.manifest_parser import parse

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.device" android:versionName="1.0">
    <application android:label="{label}"/>
</manifest>
"""

_STRINGS = """<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">R2-D2</string>
    <string name="other">Other</string>
</resources>
"""


def _apk_dir(tmp_path: Path, label: str, strings: bool = True) -> Path:
    res = tmp_path / "resources"
    (res / "res" / "values").mkdir(parents=True)
    (res / "AndroidManifest.xml").write_text(_MANIFEST.format(label=label))
    if strings:
        (res / "res" / "values" / "strings.xml").write_text(_STRINGS)
    return tmp_path


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("@string/app_name", "R2-D2"),
        ("My Robot", "My Robot"),
        ("@string/missing", None),
        ("@mipmap/ic_launcher", None),  # not a string resource
    ],
)
def test_app_label_resolution(tmp_path: Path, label: str, expected: str | None) -> None:
    assert parse(_apk_dir(tmp_path, label)).app_label == expected


def test_app_label_without_strings_xml(tmp_path: Path) -> None:
    assert parse(_apk_dir(tmp_path, "@string/app_name", strings=False)).app_label is None
