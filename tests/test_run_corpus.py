# SPDX-License-Identifier: MIT
"""Tests for the corpus runner's verdict matching and fixture list."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.run_corpus import _apk_path, _matches


@pytest.mark.parametrize(
    ("expected", "verdict", "ok"),
    [
        ("skip", "skip:duplicate", True),
        ("skip", "skip:tuya", True),
        ("skip", "proceed", False),
        ("proceed", "proceed", True),
        ("proceed", "error", False),
        (None, "proceed", None),
    ],
)
def test_matches(expected: str | None, verdict: str, ok: bool | None) -> None:
    entry = {"id": "x"} | ({"expected_verdict": expected} if expected else {})

    assert _matches(entry, {"verdict": verdict}) is ok


def test_sources_are_pinned_fdroid_or_placeholder() -> None:
    sources = Path(__file__).parents[1] / "fixtures" / "sources.yaml"
    entries = yaml.safe_load(sources.read_text())["apks"]

    for e in entries:
        url = e["apk_url"]
        assert url.startswith("https://f-droid.org/repo/") or "example.invalid" in url, e["id"]
        if url.startswith("https://f-droid.org/repo/"):
            assert url.endswith(f"{e['package']}_{e['version_code']}.apk"), e["id"]
        assert _apk_path(e).is_relative_to(Path(__file__).parents[1] / "fixtures"), e["id"]
