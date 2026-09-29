# SPDX-License-Identifier: MIT
"""Tests for command/state → HA entity mapping in the emitter context."""

from __future__ import annotations

from typing import Any

from engine.emitters import context as ctx_mod
from engine.ir.models import (
    AuthScheme,
    AuthType,
    Direction,
    DiscoveryMechanism,
    DiscoveryType,
    Endpoint,
    EntityHint,
    FieldDef,
    FieldKind,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)


def _cmd(cmd: str, hint: EntityHint, *fields: tuple[str, FieldKind]) -> Endpoint:
    return Endpoint(
        cmd=cmd,
        transport=TransportType.WEBSOCKET,
        direction=Direction.TO_DEVICE,
        entity_hint=hint,
        request_fields=[FieldDef(name=n, kind=k) for n, k in fields],
    )


def _state(name: str, kind: FieldKind, hint: EntityHint) -> FieldDef:
    return FieldDef(name=name, kind=kind, entity_hint=hint)


def _ctx(commands: list[Endpoint], fields: list[FieldDef], **extra: Any) -> dict[str, Any]:
    ir = ProtocolIR(
        apk_path="app.apk",
        package_name="com.example.device",
        app_name="Device",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=8887),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(push_cmd="state", fields=fields),
        commands=commands,
        extra=extra,
    )
    return ctx_mod.build(ir)


_ENABLE = ("enable", FieldKind.BOOLEAN)


def test_switch_backed_by_matching_state_field() -> None:
    ctx = _ctx(
        [_cmd("face_detection", EntityHint.SWITCH, _ENABLE)],
        [_state("faceDetection", FieldKind.BOOLEAN, EntityHint.BINARY_SENSOR)],
    )

    assert ctx["switches"][0]["state_attr"] == "faceDetection"


def test_switch_without_state_field_is_optimistic() -> None:
    ctx = _ctx([_cmd("power", EntityHint.SWITCH, _ENABLE)], [])

    assert ctx["switches"][0]["state_attr"] is None


def test_switch_needing_more_than_enable_is_unmapped() -> None:
    ctx = _ctx([_cmd("connectWifi", EntityHint.SWITCH, ("ssid", FieldKind.STRING), _ENABLE)], [])

    assert not ctx["switches"]
    assert ctx["unmapped_commands"][0]["cmd"] == "connectWifi"
    assert "ssid:string" in ctx["unmapped_commands"][0]["reason"]


def test_button_with_required_param_is_unmapped() -> None:
    ctx = _ctx([_cmd("move-head", EntityHint.BUTTON, ("angle", FieldKind.STRING))], [])

    assert not ctx["buttons"]
    assert ctx["unmapped_commands"][0]["cmd"] == "move-head"


def test_maintenance_buttons_flagged() -> None:
    ctx = _ctx(
        [
            _cmd("reset_mcu", EntityHint.BUTTON),
            _cmd("d-leg-power", EntityHint.BUTTON),
            _cmd("wave", EntityHint.BUTTON),
        ],
        [],
    )

    flags = {b["cmd"]: (b["maintenance"], b["device_class"]) for b in ctx["buttons"]}
    assert flags == {
        "reset_mcu": (True, "restart"),
        "d-leg-power": (True, None),
        "wave": (False, None),
    }


def test_number_needs_exactly_one_numeric_param() -> None:
    ctx = _ctx(
        [
            _cmd("volume", EntityHint.NUMBER, ("level", FieldKind.INTEGER)),
            _cmd(
                "head-shift",
                EntityHint.NUMBER,
                ("angle", FieldKind.INTEGER),
                ("speed", FieldKind.INTEGER),
            ),
        ],
        [],
    )

    assert [(n["cmd"], n["param"]) for n in ctx["numbers"]] == [("volume", "level")]
    assert [u["cmd"] for u in ctx["unmapped_commands"]] == ["head-shift"]


def test_select_requires_known_options_and_reads_state() -> None:
    mode_state = [_state("mode", FieldKind.INTEGER, EntityHint.SENSOR)]
    select = [_cmd("mode", EntityHint.SELECT, ("mode", FieldKind.INTEGER))]

    assert not _ctx(select, mode_state)["selects"]
    ctx = _ctx(select, mode_state, mode_actions={"0": "idle", "1": "dance"})
    assert ctx["selects"][0]["options"] == ["idle", "dance"]
    assert ctx["selects"][0]["state_attr"] == "mode"


def test_device_classes_and_translation_keys() -> None:
    ctx = _ctx(
        [],
        [
            _state("battery", FieldKind.INTEGER, EntityHint.SENSOR),
            _state("isCharging", FieldKind.BOOLEAN, EntityHint.BINARY_SENSOR),
        ],
    )

    battery = ctx["sensors"][0]
    assert (battery["device_class"], battery["unit"], battery["state_class"]) == (
        "battery",
        "%",
        "measurement",
    )
    assert ctx["binary_sensors"][0]["device_class"] == "battery_charging"
    assert ctx["binary_sensors"][0]["tkey"] == "ischarging"
    assert "ischarging" in ctx["entity_sections"]["binary_sensor"]
