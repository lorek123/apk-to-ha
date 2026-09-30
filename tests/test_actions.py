# SPDX-License-Identifier: MIT
"""P5 actions: naming, parameter placement, selectors and strings."""

from __future__ import annotations

from engine.emitters import actions
from engine.ir.models import Direction, Endpoint, FieldDef, FieldKind, TransportType

_HTTP = TransportType.HTTP_REST


def _ep(cmd: str, *fields: FieldDef, transport: TransportType = _HTTP) -> Endpoint:
    return Endpoint(
        cmd=cmd, transport=transport, direction=Direction.TO_DEVICE, request_fields=list(fields)
    )


def _f(name: str, kind: FieldKind = FieldKind.STRING, **kw: object) -> FieldDef:
    return FieldDef(name=name, kind=kind, **kw)


def test_names_drop_api_segments_and_prefix_verbs_on_clash() -> None:
    body = _f("body", FieldKind.OBJECT, location="body")
    built, _ = actions.build(
        [
            (_ep("GET /api/settings"), [], True),
            (_ep("POST /api/settings", body), [body], False),
            (_ep("POST /api/v1/mkdir"), [], False),
        ],
        "dev",
    )

    assert [a["name"] for a in built] == ["get_settings", "post_settings", "mkdir"]


def test_reserved_and_keyword_names_are_prefixed() -> None:
    built, _ = actions.build(
        [(_ep("disconnect", transport=TransportType.WEBSOCKET), [], False)], "dev"
    )

    assert built[0]["name"] == "do_disconnect"


def test_http_parameter_locations() -> None:
    q, form, axis = _f("path", location="query"), _f("name", location="form"), _f("axis")
    j = _f("speed", FieldKind.NUMBER)
    built, _ = actions.build(
        [
            (_ep("GET /api/files", q), [q], True),
            (_ep("POST /mkdir", form), [form], False),
            (_ep("POST /home/{axis}"), [axis], False),
            (_ep("POST /jog", j), [j], False),
            (_ep("DELETE /item", _f("id")), [_f("id")], False),
        ],
        "dev",
    )
    loc = {a["name"]: [(f["arg"], f["location"]) for f in a["fields"]] for a in built}

    assert loc == {
        "files": [("path", "query")],
        "mkdir": [("name", "form")],
        "home": [("axis", "path")],
        "jog": [("speed", "json")],
        "item": [("id", "query")],  # no body on DELETE by default
    }
    home = next(a for a in built if a["name"] == "home")
    assert home["path_expr"] == 'f"/home/{quote(str(axis), safe="")}"'
    assert home["groups"] == []


def test_optional_fields_follow_required_ones() -> None:
    tail = _f("tail", FieldKind.INTEGER, required=False)
    ep = _ep("QUERY FetchLogs", _f("id"), tail, transport=TransportType.GRAPHQL)
    (action,), _ = actions.build([(ep, [_f("id")], True)], "dev")

    assert action["signature"] == ["*,", "id: str,", "tail: int | None = None,"]
    assert [(f["arg"], f["required"]) for f in action["fields"]] == [("id", True), ("tail", False)]
    assert action["sample_data"] == {"id": "test"}


def test_push_transport_queries_stay_unmapped() -> None:
    built, unmapped = actions.build(
        [(_ep("getWifiList", transport=TransportType.WEBSOCKET), [], True)], "dev"
    )

    assert not built
    assert "no reply" in unmapped[0]["reason"]


def test_ble_commands_are_not_actions() -> None:
    built, unmapped = actions.build(
        [(_ep("clientKey", transport=TransportType.BLE), [], False)], "dev"
    )

    assert built == unmapped == []


def test_selectors_and_strings() -> None:
    pw = _f("wifi_pw")
    mode = _f("mode", enum_values=["eco", "boost"])
    ep = _ep("join", pw, mode, transport=TransportType.WEBSOCKET)
    built, _ = actions.build([(ep, [pw, mode], False)], "dev")

    fields = actions.services_yaml(built, "dev")["join"]["fields"]
    assert fields["config_entry_id"]["selector"] == {"config_entry": {"integration": "dev"}}
    assert fields["wifi_pw"]["selector"] == {"text": {"type": "password"}}
    assert fields["mode"]["selector"] == {"select": {"options": ["eco", "boost"]}}
    strings = actions.strings(built, "Device")
    assert set(strings["services"]["join"]["fields"]) == {"config_entry_id", "wifi_pw", "mode"}
    assert set(strings["exceptions"]) == {"entry_not_found", "entry_not_loaded", "action_failed"}
    assert actions.strings([], "Device") == {}
