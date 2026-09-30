# SPDX-License-Identifier: MIT
"""Build the template context dict from a ProtocolIR."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from ..extraction.signing_emitter import build as build_signing_ctx
from ..ir.models import (
    AuthType,
    Direction,
    DiscoveryType,
    Endpoint,
    EntityHint,
    FieldDef,
    FieldKind,
    ProtocolIR,
    StreamingContract,
    TransportType,
)
from . import actions as actions_mod
from . import gatt as gatt_mod

_HA_TARGET = Path(__file__).parents[3] / "config" / "ha_target.toml"

# Commands that are auth / discovery / internal — never emit as HA entities
_SKIP_CMDS = {
    "grantAccess",
    "updBroadcast",
    "streaming",
    "gin",
    "user_control",
}


def _to_snake(camel: str) -> str:
    """'batteryLevel' → 'battery_level', preserves existing underscores."""
    s = re.sub(r"([A-Z])", r"_\1", camel).lower().lstrip("_")
    return re.sub(r"[^a-z0-9_]", "_", s)


def _slugify(text: str) -> str:
    """Package/domain slug: lowercase letters and digits only, underscores for separators."""
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")


# Maintenance/debug commands: config category, disabled by default.
_MAINTENANCE_CMD = re.compile(
    r"^d[-_]|reset|reboot|restart|shutdown|poweroff|debug|factory|calibrat|firmware|update"
    r"|delete|force"
    # stopping a whole array/system takes everything on it down (Unraid StopArray)
    r"|stop_?(?:array|system|server|all)",
    re.IGNORECASE,
)
_RESTART_CMD = re.compile(r"reset|reboot|restart", re.IGNORECASE)

# Request fields the transport fills in itself, never an entity.
_TRANSPORT_FIELDS = frozenset({"cmd", "seq"})

# State key substring → (device_class, unit, state_class). Only safe, unit-free
# inferences: a "battery" level is a percentage by HA convention.
_SENSOR_CLASSES: dict[str, tuple[str, str | None, str | None]] = {
    "battery": ("battery", "%", "measurement"),
}
_BINARY_SENSOR_CLASSES: dict[str, str] = {
    "charging": "battery_charging",
    "connected": "connectivity",
    "online": "connectivity",
}


def _norm(name: str) -> str:
    """'face_detection', 'faceDetection', 'face-detection' → 'facedetection'."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _match_class[T](key: str, table: dict[str, T]) -> T | None:
    k = _norm(key)
    return next((v for sub, v in table.items() if sub in k), None)


_RESULT_FIELD_RE = re.compile(r"^(?:resultcode|result|code|errorcode|status)$")


def _auth_result_field(ir: ProtocolIR) -> str | None:
    """Wire name of the integer status in the handshake reply (e.g. resultCode), if known.

    Lets the SDK tell a rejected pairing apart from an unreachable device.
    """
    auth = next((c for c in ir.commands if c.cmd == ir.auth.handshake_cmd), None)
    for f in auth.response_fields if auth else []:
        name = f.serialized_name or f.name
        if f.kind == FieldKind.INTEGER and _RESULT_FIELD_RE.match(_norm(name)):
            return name
    return None


# Commands that fetch data rather than act (getWifiList, paired_list, fetchStatus,
# and any HTTP GET).
_QUERY_CMD = re.compile(r"^(?:get|list|fetch|query|read)|list$|status$", re.IGNORECASE)


def _is_query(ep: Endpoint) -> bool:
    """A reply carrying data beyond a status code, or a query-like name."""
    data = [
        f
        for f in ep.response_fields
        if not _RESULT_FIELD_RE.match(_norm(f.serialized_name or f.name))
    ]
    if ep.cmd.startswith(("GET ", "QUERY ")):
        return True
    return bool(data) or bool(_QUERY_CMD.search(_norm(ep.cmd)))


# GraphQL operations are named "MUTATION StartArray" / "QUERY GetMetrics".
_GRAPHQL_CMD = re.compile(r"^(QUERY|MUTATION|SUBSCRIPTION) (\w+)$")

# HTTP endpoints are named "VERB /path/{param}".
_HTTP_CMD = re.compile(r"^([A-Z]+) (/\S*)$")
_PATH_PARAM = re.compile(r"\{(\w+)\}")


def _http_key(path: str) -> str:
    """Entity/SDK key from a path's fixed segments: /goto/radec → goto_radec."""
    fixed = [s for s in path.split("/") if s and not _PATH_PARAM.fullmatch(s)]
    return _slugify("_".join(fixed)) or "root"


_CURVE_CLASSES = {"p256": "SECP256R1", "p384": "SECP384R1"}


def challenge_ctx(ir: ProtocolIR) -> dict[str, Any] | None:
    """Template view of a complete challenge-response profile, with characteristic UUIDs."""
    profile = ir.auth.challenge
    if ir.auth.type != AuthType.CHALLENGE_RESPONSE or profile is None or profile.missing:
        return None
    uuids: dict[str, str] = ir.extra.get("ble_char_uuids", {})
    roles = {
        "challenge": profile.challenge,
        "proof": profile.proof,
        "ack": profile.ack,
        "client_key": profile.client_key,
        "client_nonce": profile.client_nonce,
        "action": profile.action,
    }
    role_uuids = {role: uuids.get(cmd) for role, cmd in roles.items() if cmd}
    if any(u is None for u in role_uuids.values()):
        return None  # a role without a known characteristic UUID can't be driven
    curve = (profile.algorithm or "").split("-")[1] if profile.algorithm else ""
    if curve not in _CURVE_CLASSES:
        return None
    return {
        **{f"{role}_uuid": u for role, u in role_uuids.items()},
        "message": profile.message,
        "curve_class": _CURVE_CLASSES[curve],
        "coord_bytes": 32 if curve == "p256" else 48,
        "raw_signature": profile.signature_encoding == "raw_rs",
        "compressed_key": profile.public_key_encoding == "sec1_compressed",
        "client_nonce_length": profile.client_nonce_length,
        "primary_action": profile.primary_action,
        "probe_action": profile.probe_action,
        "implicit_action": profile.implicit_action,
        "service_uuids": ir.extra.get("ble_service_uuids", []),
    }


def _required_params(ep: Endpoint) -> list[FieldDef]:
    """Body fields plus path placeholders (/home/{axis} needs an axis too)."""
    params = [f for f in ep.request_fields if f.required and f.name not in _TRANSPORT_FIELDS]
    http = _HTTP_CMD.match(ep.cmd)
    if http:
        params += [
            FieldDef(name=p, kind=FieldKind.STRING) for p in _PATH_PARAM.findall(http.group(2))
        ]
    return params


def _unmapped(cmd: str, platform: str, params: list[FieldDef]) -> dict[str, str]:
    needs = ", ".join(f"{f.name}:{f.kind.value}" for f in params) or "nothing"
    return {"cmd": cmd, "reason": f"{platform} can't supply required params ({needs})"}


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


# Package suffixes that name the platform, not the product: dev.inkcast.aos → inkcast.
_GENERIC_SEGMENTS = frozenset(
    {"android", "aos", "app", "apps", "client", "droid", "mobile", "phone", "release"}
)


def _domain_segment(package_name: str) -> str:
    """The package's last product-naming segment."""
    segments = [s.lower() for s in package_name.split(".") if s]
    named = [s for s in segments[1:] if s not in _GENERIC_SEGMENTS]
    return named[-1] if named else segments[-1]


def _human(slug: str) -> str:
    """'face_detection' → 'Face detection', 'r2d2' → 'R2D2'"""
    return slug.replace("_", " ").replace("-", " ").capitalize()


def build(ir: ProtocolIR) -> dict[str, Any]:
    with _HA_TARGET.open("rb") as fh:
        ha_cfg = tomllib.load(fh)

    domain = _slugify(_domain_segment(ir.package_name))
    class_pfx = _class_prefix(domain)
    sdk_pkg = f"{domain}_sdk"
    # Strip version/build suffixes from APK filename:
    #   "Build Your Own R2-D2_1.1.31_release_APKPure" → "Build Your Own R2-D2"
    clean_name = re.sub(r"[_\s]+\d[\d.]+.*$", "", ir.app_name).replace("_", " ").strip()
    if not clean_name:
        clean_name = ir.app_name
    mode_actions: dict[int, str] = {int(k): v for k, v in ir.extra.get("mode_actions", {}).items()}

    # ── state fields → sensors (first: commands match against them) ──────────
    sensors, binary_sensors = [], []
    for f in ir.state.fields:
        if f.entity_hint is None:
            continue  # metadata field — not a HA entity
        key = f.serialized_name or f.name
        spec: dict[str, Any] = {
            "key": key,
            "tkey": _slugify(key),
            "name": _human(key),
            "attr": f.name,
        }
        if f.entity_hint == EntityHint.BINARY_SENSOR:
            spec["device_class"] = _match_class(key, _BINARY_SENSOR_CLASSES)
            binary_sensors.append(spec)
        else:
            sensor_class = _match_class(key, _SENSOR_CLASSES)
            spec.update(
                device_class=sensor_class[0] if sensor_class else None,
                unit=sensor_class[1] if sensor_class else None,
                state_class=sensor_class[2] if sensor_class else None,
            )
            sensors.append(spec)
    state_attrs = {_norm(s["key"]): s["attr"] for s in sensors + binary_sensors}
    state_attrs |= {_norm(s["attr"]): s["attr"] for s in sensors + binary_sensors}

    # ── categorise commands ───────────────────────────────────────────────────
    # A command becomes an entity only if the entity can supply every required
    # parameter; otherwise sending it would be malformed. Those are reported.
    switches, buttons, selects, numbers = [], [], [], []
    unmapped: list[dict[str, str]] = []
    # Commands no entity can drive: (endpoint, required params, is a query) → actions.
    action_candidates: list[tuple[Endpoint, list[FieldDef], bool]] = []
    polled = {ir.state.poll_endpoint, *ir.state.poll_endpoints}
    for ep in ir.commands:
        if ep.cmd in _SKIP_CMDS:
            continue
        params = _required_params(ep)
        http = _HTTP_CMD.match(ep.cmd)
        gql = _GRAPHQL_CMD.match(ep.cmd)
        if http:
            key = _http_key(http.group(2))
        elif gql:
            key = _to_snake(gql.group(2))  # MUTATION StartArray → start_array
        else:
            key = _slugify(ep.cmd)
        base = {
            "cmd": ep.cmd,
            "name": _human(key),
            "key": key,
            "tkey": key,
            "state_attr": state_attrs.get(_norm(key)),
            "http_method": http.group(1) if http else None,
            "path": http.group(2) if http else None,
            "operation": gql.group(2) if gql else None,
            "document": ep.document,
        }
        if ep.entity_hint == EntityHint.SWITCH:
            if [(f.name, f.kind) for f in params] != [("enable", FieldKind.BOOLEAN)]:
                unmapped.append(_unmapped(ep.cmd, "switch", params))
                action_candidates.append((ep, params, _is_query(ep)))
                continue
            switches.append(base)
        elif ep.entity_hint == EntityHint.SELECT:
            if not mode_actions:
                unmapped.append({"cmd": ep.cmd, "reason": "select without known options"})
                continue
            selects.append({**base, "options": list(mode_actions.values())})
        elif ep.entity_hint == EntityHint.NUMBER:
            numeric = [f for f in params if f.kind in (FieldKind.INTEGER, FieldKind.NUMBER)]
            if len(params) != 1 or len(numeric) != 1:
                unmapped.append(_unmapped(ep.cmd, "number", params))
                action_candidates.append((ep, params, _is_query(ep)))
                continue
            numbers.append({**base, "param": numeric[0].name, "param_kind": numeric[0].kind.value})
        elif ep.entity_hint == EntityHint.BUTTON:
            if params:
                unmapped.append(_unmapped(ep.cmd, "button", params))
                action_candidates.append((ep, params, _is_query(ep)))
                continue
            if _is_query(ep):
                unmapped.append({"cmd": ep.cmd, "reason": "query: a button can't show its reply"})
                if ep.cmd not in polled:  # polled queries already feed the state
                    action_candidates.append((ep, params, True))
                continue
            maintenance = bool(_MAINTENANCE_CMD.search(ep.cmd))
            buttons.append(
                {
                    **base,
                    "maintenance": maintenance,
                    "device_class": "restart" if _RESTART_CMD.search(ep.cmd) else None,
                }
            )

    # Actions replace the "unmapped" report for the commands they cover.
    actions, action_unmapped = actions_mod.build(action_candidates, domain)
    covered = {a["cmd"] for a in actions} | {u["cmd"] for u in action_unmapped}
    unmapped = [u for u in unmapped if u["cmd"] not in covered] + action_unmapped

    # Every state field stays in the SDK's state model, but a field already shown
    # by a control (mute switch, mode select) doesn't also get its own sensor.
    model_sensors, model_binary_sensors = sensors, binary_sensors
    consumed = {c["state_attr"] for c in switches + selects + numbers if c["state_attr"]}
    sensors = [s for s in sensors if s["attr"] not in consumed]
    binary_sensors = [s for s in binary_sensors if s["attr"] not in consumed]

    # ── P5-7 discovery blocks for manifest.json + config_flow ────────────────
    zeroconf_types: list[str] = []
    dhcp_hostnames: list[str] = []
    if ir.discovery.type == DiscoveryType.ZEROCONF and ir.discovery.service_type:
        zeroconf_types = [ir.discovery.service_type]
    # Only emit a DHCP matcher for a hostname pattern the app actually uses; an
    # invented pattern would either never match or match unrelated devices.
    if ir.discovery.hostname_pattern:
        dhcp_hostnames = [ir.discovery.hostname_pattern]

    # ── BLE characteristics for P4-6 Bleak client template ───────────────────
    ble_char_uuids: dict[str, str] = ir.extra.get("ble_char_uuids", {})
    ble_char_access: dict[str, list[str]] = ir.extra.get("ble_char_access", {})
    ble_chars: list[dict[str, Any]] = []
    for ep in ir.commands + ir.events:
        if ep.transport != TransportType.BLE:
            continue
        uuid = ble_char_uuids.get(ep.cmd)
        if not uuid:
            continue
        access: list[str] = list(ble_char_access.get(ep.cmd, []))
        if not access:
            access = ["write"] if ep.direction == Direction.TO_DEVICE else ["read"]
        ble_chars.append(
            {
                "cmd": ep.cmd,
                "key": _to_snake(ep.cmd),
                "uuid": uuid,
                "access": access,
            }
        )
    # De-duplicate by UUID (same char may appear in both commands and events)
    seen_uuids: set[str] = set()
    deduped_ble: list[dict[str, Any]] = []
    for ch in ble_chars:
        if ch["uuid"] not in seen_uuids:
            seen_uuids.add(ch["uuid"])
            deduped_ble.append(ch)
    ble_chars = deduped_ble

    # Derived entity lists for BLE platform emission
    ble_sensors: list[dict[str, Any]] = [
        {**ch, "name": _human(ch["cmd"]), "tkey": _slugify(ch["key"])}
        for ch in ble_chars
        if "notify" in ch["access"] or "read" in ch["access"]
    ]
    ble_switches: list[dict[str, Any]] = [
        {**ch, "name": _human(ch["cmd"]), "tkey": _slugify(ch["key"])}
        for ch in ble_chars
        if "write" in ch["access"]
    ]

    # ── P5-6 Android string resources → HA translation strings ───────────────
    android_strings: dict[str, str] = ir.extra.get("android_strings", {})
    device_errors: list[dict[str, Any]] = []
    for raw_key, msg in android_strings.items():
        k_lower = raw_key.lower()
        if any(t in k_lower for t in ("error", "fail", "warn", "alert", "unavail")):
            device_errors.append({"key": _to_snake(raw_key), "msg": msg})

    # Entity name translations for translations/en.json (Gold rule)
    all_sensors = sensors + (ble_sensors or [])
    all_switches = switches + (ble_switches or [])
    entity_sections: dict[str, dict[str, Any]] = {}
    if all_sensors:
        entity_sections["sensor"] = {str(s["tkey"]): {"name": s["name"]} for s in all_sensors}
    if binary_sensors:
        entity_sections["binary_sensor"] = {
            str(s["tkey"]): {"name": s["name"]} for s in binary_sensors
        }
    if all_switches:
        entity_sections["switch"] = {str(s["tkey"]): {"name": s["name"]} for s in all_switches}
    if buttons:
        entity_sections["button"] = {str(s["tkey"]): {"name": s["name"]} for s in buttons}
    if selects:
        entity_sections["select"] = {str(s["tkey"]): {"name": s["name"]} for s in selects}
    if numbers:
        entity_sections["number"] = {str(s["tkey"]): {"name": s["name"]} for s in numbers}

    # ── Camera / video stream ─────────────────────────────────────────────────
    streaming: StreamingContract | None = ir.streaming
    has_camera = streaming is not None
    video_port: int = streaming.port if streaming else 0
    video_frame_format: str = streaming.frame_format if streaming else "jpeg"
    video_rotate_degrees: int = streaming.rotate_degrees if streaming else 0

    if has_camera:
        entity_sections["camera"] = {"stream": {"name": "Camera"}}

    challenge = challenge_ctx(ir)
    gatt = gatt_mod.build(ir, domain)
    if gatt:
        unmapped += gatt["unmapped"]
    ps = ir.play_store
    return {
        # identifiers
        "domain": domain,
        "name": clean_name,
        "class_prefix": class_pfx,
        "sdk_package": sdk_pkg,
        "integration_version": "0.1.0",
        "ha_min_version": ha_cfg["target"]["generated_minimum_required"],
        "iot_class": _infer_iot_class(ir.transport.type),
        # play store context
        "app_description": ps.description if ps else "",
        "app_summary": (ps.summary or ps.description[:200]) if ps else "",
        "play_category": (ps.category or "") if ps else "",
        "play_developer": (ps.developer or "") if ps else "",
        # transport
        "ws_port": ir.transport.port or 8887,
        "udp_port": ir.discovery.port,
        "udp_broadcast_cmd": ir.discovery.broadcast_cmd,
        # discovery.py broadcasts CMD_DISCOVERY on UDP_PORT: needs both.
        "has_udp_discovery": bool(ir.discovery.port and ir.discovery.broadcast_cmd),
        "transport": ir.transport.type.value,
        # GraphQL: endpoint path, API-key header and the queries polled for state.
        "graphql_path": ir.extra.get("graphql_path", "/graphql"),
        "api_key_header": (
            ir.auth.fields[0].name if ir.auth.type == AuthType.API_KEY and ir.auth.fields else None
        ),
        "poll_queries": [
            {"name": c.cmd.split(" ", 1)[1], "document": c.document}
            for c in ir.commands
            if c.cmd in ir.state.poll_endpoints
        ],
        # BLE devices that verify signed challenges (None unless the profile is complete).
        "challenge": challenge,
        "has_challenge_auth": challenge is not None,
        # BLE devices without authentication: GATT reads and one-byte writes.
        "gatt": gatt,
        "has_gatt": gatt is not None,
        # Poll-based HTTP devices: the GET that returns state ("GET /status").
        "poll_method": ir.state.poll_endpoint.split(" ", 1)[0] if ir.state.poll_endpoint else None,
        "poll_path": ir.state.poll_endpoint.split(" ", 1)[1] if ir.state.poll_endpoint else None,
        "auth_cmd": ir.auth.handshake_cmd or "grantAccess",
        "auth_result_field": _auth_result_field(ir),
        "state_push_cmd": ir.state.push_cmd or "gin",
        # entities
        "switches": switches,
        "buttons": buttons,
        "selects": selects,
        "numbers": numbers,
        "sensors": sensors,
        "binary_sensors": binary_sensors,
        "model_sensors": model_sensors,
        "model_binary_sensors": model_binary_sensors,
        "unmapped_commands": unmapped,
        # P5 actions: commands with parameters, and queries that return a reply.
        "actions": actions,
        "services_yaml": actions_mod.services_yaml(actions, domain),
        "action_strings": actions_mod.strings(actions, clean_name),
        "mode_actions": mode_actions,
        # platforms present
        "platforms": _platforms(
            switches,
            buttons,
            selects,
            numbers,
            sensors,
            binary_sensors,
            ble_sensors,
            ble_switches,
            has_camera=has_camera,
        ),
        # P5-7 discovery
        "has_zeroconf": bool(zeroconf_types),
        "has_dhcp": bool(dhcp_hostnames),
        "zeroconf_types": zeroconf_types,
        "dhcp_hostnames": dhcp_hostnames,
        # P4-6 BLE client + P5-8 BLE entity mapping
        "has_ble": bool(ble_chars),
        "ble_chars": ble_chars,
        "ble_sensors": ble_sensors,
        "ble_switches": ble_switches,
        "ble_service_uuids": ir.extra.get("ble_service_uuids", []),
        # P5-6 translation strings
        "device_errors": device_errors,
        "entity_sections": entity_sections,
        # camera
        "has_camera": has_camera,
        "video_port": video_port,
        "video_frame_format": video_frame_format,
        "video_rotate_degrees": video_rotate_degrees,
        # P2-6 signing (merged in; has_signing=False when no trace)
        **build_signing_ctx(ir.signing_traces),
    }


def _infer_iot_class(transport_type: TransportType) -> str:
    return {
        TransportType.WEBSOCKET: "local_push",
        TransportType.HTTP_REST: "local_polling",
        TransportType.BLE: "local_push",
        TransportType.UDP: "local_push",
        TransportType.TCP_SOCKET: "local_push",
    }.get(transport_type, "local_polling")


def _platforms(
    switches: list[Any],
    buttons: list[Any],
    selects: list[Any],
    numbers: list[Any],
    sensors: list[Any],
    binary_sensors: list[Any],
    ble_sensors: list[Any] | None = None,
    ble_switches: list[Any] | None = None,
    has_camera: bool = False,
) -> list[str]:
    plats = []
    if sensors or ble_sensors:
        plats.append("sensor")
    if binary_sensors:
        plats.append("binary_sensor")
    if switches or ble_switches:
        plats.append("switch")
    if buttons:
        plats.append("button")
    if selects:
        plats.append("select")
    if numbers:
        plats.append("number")
    if has_camera:
        plats.append("camera")
    return plats
