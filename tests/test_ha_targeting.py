# SPDX-License-Identifier: MIT
"""F-7 — HA version targeting propagation tests.

Verifies that changing ha_target.toml flows correctly into:
  - the emitter context dict (ha_min_version)
  - the emitted manifest.json (homeassistant field)
  - the bump script (all version fields updated consistently)
"""
from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]
_HA_TARGET = _ROOT / "config" / "ha_target.toml"


# ── ha_target.toml structure ─────────────────────────────────────────────────

def test_ha_target_exists() -> None:
    assert _HA_TARGET.exists()


def test_ha_target_required_sections() -> None:
    with open(_HA_TARGET, "rb") as f:
        cfg = tomllib.load(f)
    assert "target" in cfg
    assert "docker" in cfg
    assert "anchors" in cfg
    assert "sandbox" in cfg


def test_ha_target_required_keys() -> None:
    with open(_HA_TARGET, "rb") as f:
        cfg = tomllib.load(f)
    t = cfg["target"]
    assert "ha_core_version" in t
    assert "python_version" in t
    assert "quality_scale_target" in t
    assert "generated_minimum_required" in t

    d = cfg["docker"]
    assert "ha_image" in d
    assert "ha_image_tag" in d

    s = cfg["sandbox"]
    assert "image" in s
    assert "tag" in s


def test_ha_image_tag_matches_core_major_minor() -> None:
    with open(_HA_TARGET, "rb") as f:
        cfg = tomllib.load(f)
    core = cfg["target"]["ha_core_version"]
    tag = cfg["docker"]["ha_image_tag"]
    assert ".".join(core.split(".")[:2]) == ".".join(tag.split(".")[:2]), (
        f"ha_image_tag {tag!r} major.minor doesn't match ha_core_version {core!r}"
    )


# ── context propagation ───────────────────────────────────────────────────────

def _make_minimal_ir():
    from engine.ir.models import (
        AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
        Framework, ProtocolIR, StateSchema, TransportContract, TransportType,
    )
    return ProtocolIR(
        apk_path="test",
        package_name="com.example.testapp",
        app_name="Test App",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.HTTP_REST, port=80, host_source="manual"),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(fields=[]),
        commands=[],
        events=[],
    )


def test_context_ha_min_version_from_toml() -> None:
    from engine.emitters.context import build
    with open(_HA_TARGET, "rb") as f:
        expected = tomllib.load(f)["target"]["generated_minimum_required"]
    ctx = build(_make_minimal_ir())
    assert ctx["ha_min_version"] == expected


def test_context_iot_class_http_rest_is_local_polling() -> None:
    from engine.emitters.context import build
    ctx = build(_make_minimal_ir())
    assert ctx["iot_class"] == "local_polling"


def test_context_iot_class_websocket_is_local_push() -> None:
    from engine.ir.models import (
        AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
        Framework, ProtocolIR, StateSchema, TransportContract, TransportType,
    )
    from engine.emitters.context import build
    ir = ProtocolIR(
        apk_path="test",
        package_name="com.example.wsapp",
        app_name="WS App",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887, host_source="manual"),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(fields=[]),
        commands=[],
        events=[],
    )
    ctx = build(ir)
    assert ctx["iot_class"] == "local_push"


# ── manifest propagation ──────────────────────────────────────────────────────

def test_emitted_manifest_embeds_ha_min_version(tmp_path: Path) -> None:
    from engine.emitters import hacs_emitter
    from engine.emitters.context import build
    with open(_HA_TARGET, "rb") as f:
        expected = tomllib.load(f)["target"]["generated_minimum_required"]
    ctx = build(_make_minimal_ir())
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)
    manifest = json.loads((hacs_dir / "manifest.json").read_text())
    assert manifest["homeassistant"] == expected


def test_emitted_manifest_iot_class_http_rest(tmp_path: Path) -> None:
    from engine.emitters import hacs_emitter
    from engine.emitters.context import build
    ctx = build(_make_minimal_ir())
    hacs_dir = hacs_emitter.emit(ctx, tmp_path)
    manifest = json.loads((hacs_dir / "manifest.json").read_text())
    assert manifest["iot_class"] == "local_polling"


# ── bump script ───────────────────────────────────────────────────────────────

def test_bump_script_updates_all_fields(tmp_path: Path) -> None:
    import shutil
    from scripts.bump_ha_version import bump  # type: ignore[import]

    target_copy = tmp_path / "ha_target.toml"
    shutil.copy(_HA_TARGET, target_copy)

    bump("2099.12.3", target=target_copy)

    with open(target_copy, "rb") as f:
        cfg = tomllib.load(f)

    assert cfg["target"]["ha_core_version"] == "2099.12.3"
    assert cfg["docker"]["ha_image_tag"] == "2099.12.3"
    assert cfg["anchors"]["ref"] == "2099.12.3"
    assert cfg["target"]["generated_minimum_required"] == "2099.12.0"


def test_bump_script_strips_leading_v(tmp_path: Path) -> None:
    import shutil
    from scripts.bump_ha_version import bump  # type: ignore[import]

    target_copy = tmp_path / "ha_target.toml"
    shutil.copy(_HA_TARGET, target_copy)

    bump("v2099.1.0", target=target_copy)

    with open(target_copy, "rb") as f:
        cfg = tomllib.load(f)
    assert cfg["target"]["ha_core_version"] == "2099.1.0"
