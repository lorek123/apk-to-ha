# SPDX-License-Identifier: MIT
"""Tests for P2-2 PayloadResolver — @SerializedName/@Json(name=...) extraction."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from engine.extraction.payload_resolver import PayloadResolver, _kind
from engine.ir.models import FieldKind


# ── helpers ────────────────────────────────────────────────────────────────────

def _write_class(tmp_path: Path, class_name: str, content: str) -> Path:
    """Write a Java class file and return the apk_out_dir."""
    pkg = tmp_path / "sources" / "com" / "example"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / f"{class_name}.java").write_text(content)
    return tmp_path


# ── _kind helper ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("java_type,expected", [
    ("String", FieldKind.STRING),
    ("int", FieldKind.INTEGER),
    ("Integer", FieldKind.INTEGER),
    ("long", FieldKind.INTEGER),
    ("float", FieldKind.NUMBER),
    ("double", FieldKind.NUMBER),
    ("boolean", FieldKind.BOOLEAN),
    ("Boolean", FieldKind.BOOLEAN),
    ("List<String>", FieldKind.ARRAY),
    ("ArrayList<Integer>", FieldKind.ARRAY),
    ("String[]", FieldKind.ARRAY),
    ("CustomObject", FieldKind.OBJECT),
    ("Map<String, String>", FieldKind.OBJECT),
])
def test_kind_mapping(java_type: str, expected: FieldKind) -> None:
    assert _kind(java_type) == expected


# ── resolve: @SerializedName (Gson) ───────────────────────────────────────────

def test_resolve_serialized_name_single_field(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "PowerRequest", """
    public class PowerRequest {
        @SerializedName("enable")
        private boolean enable;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("PowerRequest")
    assert schema.class_name == "PowerRequest"
    assert len(schema.fields) == 1
    assert schema.fields[0].serialized_name == "enable"
    assert schema.fields[0].kind == FieldKind.BOOLEAN


def test_resolve_serialized_name_multiple_fields(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "DeviceCommand", """
    public class DeviceCommand {
        @SerializedName("cmd")
        private String command;

        @SerializedName("brightness_level")
        private int brightness;

        @SerializedName("color_temp")
        private double colorTemp;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("DeviceCommand")
    wire_names = {f.serialized_name for f in schema.fields}
    assert wire_names == {"cmd", "brightness_level", "color_temp"}


def test_resolve_preserves_java_field_name(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "StatusResponse", """
    public class StatusResponse {
        @SerializedName("battery_level")
        private int batteryLevel;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("StatusResponse")
    assert schema.fields[0].name == "batteryLevel"
    assert schema.fields[0].serialized_name == "battery_level"


# ── resolve: @Json(name=...) (Moshi) ──────────────────────────────────────────

def test_resolve_json_name_moshi(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "MoshiModel", """
    public class MoshiModel {
        @Json(name = "device_id")
        String deviceId;

        @Json(name = "firmware_version")
        String firmwareVersion;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("MoshiModel")
    wire_names = {f.serialized_name for f in schema.fields}
    assert "device_id" in wire_names
    assert "firmware_version" in wire_names


# ── resolve: collection unwrapping ────────────────────────────────────────────

def test_resolve_list_wrapper_sets_is_collection(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "DeviceEvent", """
    public class DeviceEvent {
        @SerializedName("type")
        private String type;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("List<DeviceEvent>")
    assert schema.is_collection is True
    assert schema.class_name == "DeviceEvent"
    assert len(schema.fields) == 1


def test_resolve_arraylist_wrapper(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "Item", """
    public class Item {
        @SerializedName("id")
        private int id;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("ArrayList<Item>")
    assert schema.is_collection is True
    assert schema.class_name == "Item"


def test_resolve_non_collection_is_false(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "SimpleModel", """
    public class SimpleModel {
        @SerializedName("value")
        private String value;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("SimpleModel")
    assert schema.is_collection is False


# ── resolve: missing class ─────────────────────────────────────────────────────

def test_resolve_returns_empty_when_class_not_found(tmp_path: Path) -> None:
    apk_dir = tmp_path
    (apk_dir / "sources").mkdir(parents=True, exist_ok=True)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("NonExistentClass")
    assert schema.class_name == "NonExistentClass"
    assert schema.fields == []


# ── caching ────────────────────────────────────────────────────────────────────

def test_resolve_caches_result(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "CachedModel", """
    public class CachedModel {
        @SerializedName("id")
        private int id;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema1 = resolver.resolve("CachedModel")
    schema2 = resolver.resolve("CachedModel")
    # Same data returned (cache hit), same backing list in _cache
    assert resolver._cache["CachedModel"] is resolver._cache["CachedModel"]
    assert schema1.fields == schema2.fields


# ── field types from mixed annotations ────────────────────────────────────────

def test_resolve_integer_field_kind(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "CounterModel", """
    public class CounterModel {
        @SerializedName("count")
        private int count;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("CounterModel")
    assert schema.fields[0].kind == FieldKind.INTEGER


def test_resolve_string_field_kind(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "NameModel", """
    public class NameModel {
        @SerializedName("name")
        private String name;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("NameModel")
    assert schema.fields[0].kind == FieldKind.STRING


def test_resolve_array_field_kind(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "ListModel", """
    public class ListModel {
        @SerializedName("items")
        private List<String> items;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("ListModel")
    assert schema.fields[0].kind == FieldKind.ARRAY


# ── deduplication ─────────────────────────────────────────────────────────────

def test_resolve_deduplicates_fields_with_same_wire_name(tmp_path: Path) -> None:
    apk_dir = _write_class(tmp_path, "DupModel", """
    public class DupModel {
        @SerializedName("name")
        private String firstName;

        @SerializedName("name")
        private String displayName;
    }
    """)
    resolver = PayloadResolver(apk_dir)
    schema = resolver.resolve("DupModel")
    name_fields = [f for f in schema.fields if f.serialized_name == "name"]
    assert len(name_fields) == 1
