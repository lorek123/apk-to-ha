# SPDX-License-Identifier: MIT
"""Tests for P5-7 discovery block emission in manifest.json and config_flow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from engine.emitters import context as ctx_mod
from engine.emitters import hacs_emitter
from engine.ir.models import (
    AuthScheme,
    AuthType,
    DiscoveryMechanism,
    DiscoveryType,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)


def _make_ir(discovery: DiscoveryMechanism, **overrides: Any) -> ProtocolIR:
    defaults = dict(
        apk_path="/tmp/test.apk",
        package_name="com.example.device",
        app_name="My Device",
        version_name="1.0.0",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887),
        discovery=discovery,
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(),
    )
    defaults.update(overrides)
    return ProtocolIR(**defaults)


def _ctx(discovery: DiscoveryMechanism, **ir_overrides: Any) -> dict[str, Any]:
    return ctx_mod.build(_make_ir(discovery, **ir_overrides))


# ── context builder ───────────────────────────────────────────────────────────


def test_has_zeroconf_true_when_type_set() -> None:
    ctx = _ctx(
        DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            service_type="_device._tcp.local.",
        )
    )
    assert ctx["has_zeroconf"] is True


def test_has_zeroconf_false_when_none() -> None:
    ctx = _ctx(DiscoveryMechanism(type=DiscoveryType.NONE))
    assert ctx["has_zeroconf"] is False


def test_zeroconf_types_populated() -> None:
    ctx = _ctx(
        DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            service_type="_lightbulb._tcp.local.",
        )
    )
    assert "_lightbulb._tcp.local." in ctx["zeroconf_types"]


def test_zeroconf_types_empty_when_no_service_type() -> None:
    ctx = _ctx(DiscoveryMechanism(type=DiscoveryType.ZEROCONF))
    assert ctx["zeroconf_types"] == []


def test_has_dhcp_from_udp_broadcast() -> None:
    ctx = _ctx(DiscoveryMechanism(type=DiscoveryType.UDP_BROADCAST, port=6445))
    assert ctx["has_dhcp"] is True


def test_dhcp_hostnames_from_udp_broadcast() -> None:
    ctx = _ctx(DiscoveryMechanism(type=DiscoveryType.UDP_BROADCAST, port=6445))
    assert len(ctx["dhcp_hostnames"]) == 1
    assert ctx["dhcp_hostnames"][0].endswith("*")


def test_has_dhcp_from_hostname_pattern() -> None:
    ctx = _ctx(
        DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            hostname_pattern="mydevice*",
        )
    )
    assert ctx["has_dhcp"] is True
    assert "mydevice*" in ctx["dhcp_hostnames"]


def test_no_discovery_both_false() -> None:
    ctx = _ctx(DiscoveryMechanism(type=DiscoveryType.NONE))
    assert ctx["has_zeroconf"] is False
    assert ctx["has_dhcp"] is False


# ── manifest.json rendering ───────────────────────────────────────────────────


def _render_manifest(tmp_path: Path, discovery: DiscoveryMechanism) -> dict[str, Any]:
    ctx = _ctx(discovery)
    hacs_emitter.emit(ctx, tmp_path)
    domain = ctx["domain"]
    manifest_path = tmp_path / "custom_components" / domain / "manifest.json"
    result: dict[str, Any] = json.loads(manifest_path.read_text())
    return result


def test_manifest_zeroconf_block(tmp_path: Path) -> None:
    manifest = _render_manifest(
        tmp_path,
        DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            service_type="_mydevice._tcp.local.",
        ),
    )
    assert "zeroconf" in manifest
    assert any(e["type"] == "_mydevice._tcp.local." for e in manifest["zeroconf"])


def test_manifest_no_zeroconf_block_when_none(tmp_path: Path) -> None:
    manifest = _render_manifest(tmp_path, DiscoveryMechanism(type=DiscoveryType.NONE))
    assert "zeroconf" not in manifest


def test_manifest_dhcp_block(tmp_path: Path) -> None:
    manifest = _render_manifest(
        tmp_path,
        DiscoveryMechanism(
            type=DiscoveryType.UDP_BROADCAST,
            port=6445,
        ),
    )
    assert "dhcp" in manifest
    assert len(manifest["dhcp"]) > 0
    assert manifest["dhcp"][0]["hostname"].endswith("*")


def test_manifest_no_dhcp_when_none(tmp_path: Path) -> None:
    manifest = _render_manifest(tmp_path, DiscoveryMechanism(type=DiscoveryType.NONE))
    assert "dhcp" not in manifest


def test_manifest_is_valid_json(tmp_path: Path) -> None:
    manifest = _render_manifest(
        tmp_path,
        DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            service_type="_device._tcp.local.",
        ),
    )
    assert isinstance(manifest, dict)
    assert manifest["config_flow"] is True


# ── config_flow rendering ─────────────────────────────────────────────────────


def _render_config_flow(tmp_path: Path, discovery: DiscoveryMechanism) -> str:
    ctx = _ctx(discovery)
    hacs_emitter.emit(ctx, tmp_path)
    domain = str(ctx["domain"])
    return (tmp_path / "custom_components" / domain / "config_flow.py").read_text()


def test_config_flow_has_zeroconf_step(tmp_path: Path) -> None:
    content = _render_config_flow(
        tmp_path,
        DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            service_type="_device._tcp.local.",
        ),
    )
    assert "async_step_zeroconf" in content


def test_config_flow_imports_zeroconf(tmp_path: Path) -> None:
    content = _render_config_flow(
        tmp_path,
        DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            service_type="_device._tcp.local.",
        ),
    )
    assert "from homeassistant.components import zeroconf" in content


def test_config_flow_zeroconf_confirm_step(tmp_path: Path) -> None:
    content = _render_config_flow(
        tmp_path,
        DiscoveryMechanism(
            type=DiscoveryType.ZEROCONF,
            service_type="_device._tcp.local.",
        ),
    )
    assert "async_step_zeroconf_confirm" in content


def test_config_flow_no_zeroconf_when_none(tmp_path: Path) -> None:
    content = _render_config_flow(tmp_path, DiscoveryMechanism(type=DiscoveryType.NONE))
    assert "async_step_zeroconf" not in content
    assert "from homeassistant.components import zeroconf" not in content


def test_config_flow_dhcp_step(tmp_path: Path) -> None:
    content = _render_config_flow(
        tmp_path,
        DiscoveryMechanism(
            type=DiscoveryType.UDP_BROADCAST,
            port=6445,
        ),
    )
    assert "async_step_dhcp" in content


def test_config_flow_imports_dhcp(tmp_path: Path) -> None:
    content = _render_config_flow(
        tmp_path,
        DiscoveryMechanism(
            type=DiscoveryType.UDP_BROADCAST,
            port=6445,
        ),
    )
    assert "from homeassistant.components import dhcp" in content


def test_config_flow_no_dhcp_when_none(tmp_path: Path) -> None:
    content = _render_config_flow(tmp_path, DiscoveryMechanism(type=DiscoveryType.NONE))
    assert "async_step_dhcp" not in content


def test_config_flow_has_spdx_header(tmp_path: Path) -> None:
    content = _render_config_flow(tmp_path, DiscoveryMechanism(type=DiscoveryType.NONE))
    assert content.splitlines()[0].startswith("# SPDX-License-Identifier: MIT")
