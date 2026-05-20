# SPDX-License-Identifier: MIT
"""Build the template context dict from a ProtocolIR."""
from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from ..ir.models import EntityHint, ProtocolIR

_HA_TARGET = Path(__file__).parents[3] / "config" / "ha_target.toml"

# Commands that are auth / discovery / internal — never emit as HA entities
_SKIP_CMDS = {
    "grantAccess",
    "updBroadcast",
    "streaming",
    "gin",
    "user_control",
}

# Commands that have an `enable` field but aren't semantic toggles
_NOT_SWITCH = {"connectWifi", "move"}


def _slugify(text: str) -> str:
    """Package/domain slug: lowercase letters and digits only, underscores for separators."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


def _class_prefix(domain: str) -> str:
    """'r2d2' → 'R2D2', 'my_device' → 'MyDevice'"""
    result = []
    for part in domain.split("_"):
        # Uppercase alphanumeric segments that contain a digit (e.g. r2d2 → R2D2)
        if any(c.isdigit() for c in part):
            result.append(part.upper())
        else:
            result.append(part.capitalize())
    return "".join(result)


def _human(slug: str) -> str:
    """'face_detection' → 'Face detection', 'r2d2' → 'R2D2'"""
    return slug.replace("_", " ").replace("-", " ").capitalize()


def build(ir: ProtocolIR) -> dict[str, Any]:
    with _HA_TARGET.open("rb") as fh:
        ha_cfg = tomllib.load(fh)

    domain = ir.package_name.split(".")[-1].lower()
    domain = _slugify(domain)
    class_pfx = _class_prefix(domain)
    sdk_pkg = f"{domain}_sdk"
    # Strip version/build suffixes from APK filename: "Build Your Own R2-D2_1.1.31_release_APKPure" → "Build Your Own R2-D2"
    clean_name = re.sub(r"[_\s]+\d[\d.]+.*$", "", ir.app_name).replace("_", " ").strip()
    if not clean_name:
        clean_name = ir.app_name
    mode_actions: dict[int, str] = {
        int(k): v for k, v in ir.extra.get("mode_actions", {}).items()
    }

    # ── categorise commands ───────────────────────────────────────────────────
    switches, buttons, selects, numbers = [], [], [], []
    for ep in ir.commands:
        if ep.cmd in _SKIP_CMDS:
            continue
        if ep.entity_hint == EntityHint.SWITCH and ep.cmd not in _NOT_SWITCH:
            switches.append({
                "cmd": ep.cmd,
                "name": _human(ep.cmd),
                "key": _slugify(ep.cmd),
            })
        elif ep.entity_hint == EntityHint.SELECT:
            options = [v for v in mode_actions.values()] if mode_actions else []
            selects.append({
                "cmd": ep.cmd,
                "name": _human(ep.cmd),
                "key": _slugify(ep.cmd),
                "options": options,
            })
        elif ep.entity_hint == EntityHint.NUMBER:
            # Emit first integer field as the number value
            int_fields = [f for f in ep.request_fields if f.name not in ("cmd", "seq")]
            selects_field = next((f for f in int_fields), None)
            numbers.append({
                "cmd": ep.cmd,
                "name": _human(ep.cmd),
                "key": _slugify(ep.cmd),
                "param": selects_field.name if selects_field else "value",
            })
        elif ep.entity_hint == EntityHint.BUTTON:
            # Skip config-only commands
            if ep.cmd in ("change_name", "paired_list", "unpair", "getWifiList"):
                continue
            buttons.append({
                "cmd": ep.cmd,
                "name": _human(ep.cmd),
                "key": _slugify(ep.cmd.replace("-", "_")),
            })

    # ── state fields → sensors ────────────────────────────────────────────────
    sensors, binary_sensors = [], []
    for f in ir.state.fields:
        spec = {
            "key": f.serialized_name or f.name,
            "name": _human(f.serialized_name or f.name),
            "attr": f.name,
        }
        if f.entity_hint == EntityHint.BINARY_SENSOR:
            binary_sensors.append(spec)
        else:
            sensors.append(spec)

    return {
        # identifiers
        "domain": domain,
        "name": clean_name,
        "class_prefix": class_pfx,
        "sdk_package": sdk_pkg,
        "integration_version": "0.1.0",
        "ha_min_version": ha_cfg["target"]["generated_minimum_required"],
        # transport
        "ws_port": ir.transport.port or 8887,
        "udp_port": ir.discovery.port,
        "udp_broadcast_cmd": ir.discovery.broadcast_cmd,
        "auth_cmd": ir.auth.handshake_cmd or "grantAccess",
        "state_push_cmd": ir.state.push_cmd or "gin",
        # entities
        "switches": switches,
        "buttons": buttons,
        "selects": selects,
        "numbers": numbers,
        "sensors": sensors,
        "binary_sensors": binary_sensors,
        "mode_actions": mode_actions,
        # platforms present
        "platforms": _platforms(switches, buttons, selects, numbers, sensors, binary_sensors),
    }


def _platforms(
    switches: list, buttons: list, selects: list, numbers: list,
    sensors: list, binary_sensors: list,
) -> list[str]:
    plats = []
    if sensors:
        plats.append("sensor")
    if binary_sensors:
        plats.append("binary_sensor")
    if switches:
        plats.append("switch")
    if buttons:
        plats.append("button")
    if selects:
        plats.append("select")
    if numbers:
        plats.append("number")
    return plats
