# SPDX-License-Identifier: MIT
"""Tests for entity hint classification."""
from __future__ import annotations

import pytest

from engine.extraction.entity_classifier import classify
from engine.ir.models import (
    Direction,
    EntityHint,
    Endpoint,
    FieldDef,
    FieldKind,
    Framework,
    ProtocolIR,
    TransportType,
)


def _make_ir(**kwargs) -> ProtocolIR:
    from engine.ir.models import (
        AuthScheme, AuthType, DiscoveryMechanism, DiscoveryType,
        StateSchema, TransportContract,
    )
    defaults = dict(
        apk_path="test.apk",
        package_name="com.test.device",
        app_name="Test Device",
        framework=Framework.NATIVE,
        transport=TransportContract(type=TransportType.WEBSOCKET, port=1234),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.NONE),
        state=StateSchema(),
        commands=[],
        events=[],
    )
    defaults.update(kwargs)
    return ProtocolIR(**defaults)


def _ep(cmd, direction=Direction.TO_DEVICE, fields=None, awaits=False):
    return Endpoint(
        cmd=cmd,
        transport=TransportType.WEBSOCKET,
        direction=direction,
        awaits_response=awaits,
        request_fields=fields or [],
    )


def _bool_field(name):
    return FieldDef(name=name, kind=FieldKind.BOOLEAN)


def _int_field(name):
    return FieldDef(name=name, kind=FieldKind.INTEGER)


# ── TO_DEVICE classification ──────────────────────────────────────────────────

def test_switch_has_enable_field():
    ir = _make_ir(commands=[_ep("mute", fields=[_bool_field("enable")])])
    result = classify(ir)
    assert result.commands[0].entity_hint == EntityHint.SWITCH


def test_button_no_fields():
    ir = _make_ir(commands=[_ep("reset_mcu")])
    result = classify(ir)
    assert result.commands[0].entity_hint == EntityHint.BUTTON


def test_select_mode_cmd_with_known_actions():
    ir = _make_ir(
        commands=[_ep("mode", fields=[_int_field("mode")])],
        extra={"mode_actions": {3: "turn_left", 4: "turn_right"}},
    )
    result = classify(ir)
    assert result.commands[0].entity_hint == EntityHint.SELECT


def test_number_integer_field_no_mode():
    ir = _make_ir(commands=[_ep("play_sound", fields=[_int_field("sound_id")])])
    result = classify(ir)
    assert result.commands[0].entity_hint == EntityHint.NUMBER


def test_from_device_always_sensor():
    ir = _make_ir(events=[_ep("gin", direction=Direction.FROM_DEVICE)])
    result = classify(ir)
    assert result.events[0].entity_hint == EntityHint.SENSOR


# ── state field classification ────────────────────────────────────────────────

def test_boolean_state_field_becomes_binary_sensor():
    from engine.ir.models import StateSchema
    ir = _make_ir(state=StateSchema(fields=[_bool_field("arm")]))
    result = classify(ir)
    assert result.state.fields[0].entity_hint == EntityHint.BINARY_SENSOR


def test_integer_state_field_becomes_sensor():
    from engine.ir.models import StateSchema
    ir = _make_ir(state=StateSchema(fields=[_int_field("battery")]))
    result = classify(ir)
    assert result.state.fields[0].entity_hint == EntityHint.SENSOR


# ── idempotency ───────────────────────────────────────────────────────────────

def test_classify_is_idempotent():
    ir = _make_ir(commands=[_ep("mute", fields=[_bool_field("enable")])])
    once = classify(ir)
    twice = classify(once)
    assert once.commands[0].entity_hint == twice.commands[0].entity_hint
