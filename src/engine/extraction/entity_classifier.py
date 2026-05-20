# SPDX-License-Identifier: MIT
"""P3-2 — Entity hint classification.

Walks the extracted IR and fills in EntityHint on every Endpoint and StateSchema
FieldDef so emitters can pick the right HA platform without re-deriving it.

Rules (in priority order):
  Endpoint TO_DEVICE:
    - has boolean "enable" field            → switch
    - cmd == "mode" or has integer "mode"
      field with known enum values          → select
    - no request fields, no awaits_response → button
    - has integer/number non-enum field     → number
    - fallback                              → button

  Endpoint FROM_DEVICE:
    - gin / state push                      → sensor (coordinator feeds it)
    - other streaming events                → sensor

  StateSchema FieldDef:
    - BOOLEAN kind                          → binary_sensor
    - INTEGER / NUMBER kind                 → sensor
    - STRING kind                           → sensor
    - OBJECT / ARRAY kind                   → sensor  (emitter may skip)
"""
from __future__ import annotations

from ..ir.models import (
    Direction,
    EntityHint,
    FieldKind,
    ProtocolIR,
)


def classify(ir: ProtocolIR) -> ProtocolIR:
    """Return a copy of *ir* with entity_hint fields populated."""
    mode_action_keys: set[int] = set(ir.extra.get("mode_actions", {}).keys())

    new_commands = [_hint_endpoint(ep, mode_action_keys) for ep in ir.commands]
    new_events = [_hint_endpoint(ep, mode_action_keys) for ep in ir.events]
    new_state_fields = [_hint_field(f) for f in ir.state.fields]
    new_state = ir.state.model_copy(update={"fields": new_state_fields})

    return ir.model_copy(update={
        "commands": new_commands,
        "events": new_events,
        "state": new_state,
    })


def _hint_endpoint(ep, mode_action_keys: set[int]):  # type: ignore[no-untyped-def]
    if ep.entity_hint is not None:
        return ep  # already set

    fields = ep.request_fields if ep.direction == Direction.TO_DEVICE else ep.response_fields

    if ep.direction == Direction.FROM_DEVICE:
        return ep.model_copy(update={"entity_hint": EntityHint.SENSOR})

    # TO_DEVICE classification
    field_names = {f.name for f in fields}
    field_kinds = {f.kind for f in fields}

    # switch: has a boolean "enable" toggle
    if "enable" in field_names or FieldKind.BOOLEAN in field_kinds:
        return ep.model_copy(update={"entity_hint": EntityHint.SWITCH})

    # select: cmd is "mode" or has an integer "mode" field with known enum values
    if ep.cmd == "mode" or (
        "mode" in field_names and FieldKind.INTEGER in field_kinds and mode_action_keys
    ):
        return ep.model_copy(update={"entity_hint": EntityHint.SELECT})

    # number: has an integer/number field that isn't a mode enum
    if field_kinds & {FieldKind.INTEGER, FieldKind.NUMBER}:
        return ep.model_copy(update={"entity_hint": EntityHint.NUMBER})

    # button: fire-and-forget with no meaningful state fields
    return ep.model_copy(update={"entity_hint": EntityHint.BUTTON})


def _hint_field(field):  # type: ignore[no-untyped-def]
    if field.entity_hint is not None:
        return field
    if field.kind == FieldKind.BOOLEAN:
        return field.model_copy(update={"entity_hint": EntityHint.BINARY_SENSOR})
    return field.model_copy(update={"entity_hint": EntityHint.SENSOR})
