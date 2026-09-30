# SPDX-License-Identifier: MIT
"""Tests for the Apollo GraphQL scanner (shapes from the F-Droid NOVA Unraid client)."""

# ruff: noqa: E501 — the Java fixtures reproduce decompiler output line for line
from __future__ import annotations

from pathlib import Path

from engine.extraction.graphql_scanner import scan
from engine.ir.models import AuthType, Direction, FieldKind, TransportType

_QUERY = """package com.example.nas.graphql;
public final class GetMetricsQuery implements Query {
    public static final String OPERATION_NAME = "GetMetrics";
    public static final class Cpu {
        private final double percentTotal;
    }
    public static final class Data implements d12 {
        private final Metrics metrics;
    }
    public static final class Memory {
        private final Long buffcache;
        private final long total;
    }
    public static final class Metrics {
        private final Cpu cpu;
        private final Memory memory;
        private final Os f5014os;
        private final List<Disk> disks;
    }
    public static final class Os {
        private final String hostname;
    }
    public static final class Companion {
        public final String getOPERATION_DOCUMENT() {
            return "query GetMetrics { metrics { cpu { percentTotal } memory { total buffcache } os { hostname } disks { name } } }";
        }
    }
}
"""

_MUTATION = """package com.example.nas.graphql;
public final class StartContainerMutation implements Mutation {
    public static final String OPERATION_NAME = "StartContainer";
    public static final class Companion {
        public final String getOPERATION_DOCUMENT() {
            return "mutation StartContainer($id: PrefixedID!, $force: Boolean) { docker { start(id: $id) { id } } }";
        }
    }
}
"""

_SUBSCRIPTION = """package com.example.nas.graphql;
public final class CpuSubscription implements Subscription {
    public static final class Companion {
        public final String getOPERATION_DOCUMENT() {
            return "subscription Cpu { systemMetricsCpu { percentTotal } }";
        }
    }
}
"""

_OBFUSCATED_AUTH = """package p000;
public final class hh {
    public final Object invoke() {
        String str4 = bz2.m767f0(str2, '/') + "/graphql";
        return Collections.singletonMap("x-api-key", str);
    }
}
"""


def _app(tmp_path: Path) -> Path:
    gql = tmp_path / "sources" / "com" / "example" / "nas" / "graphql"
    gql.mkdir(parents=True)
    (gql / "GetMetricsQuery.java").write_text(_QUERY)
    (gql / "StartContainerMutation.java").write_text(_MUTATION)
    (gql / "CpuSubscription.java").write_text(_SUBSCRIPTION)
    obf = tmp_path / "sources" / "p000"
    obf.mkdir()
    (obf / "hh.java").write_text(_OBFUSCATED_AUTH)
    return tmp_path


def test_operations_become_commands_queries_and_events(tmp_path: Path) -> None:
    result = scan(_app(tmp_path), "com.example.nas")
    assert result is not None

    assert {c.cmd for c in result.commands} == {"QUERY GetMetrics", "MUTATION StartContainer"}
    assert [e.cmd for e in result.events] == ["SUBSCRIPTION Cpu"]
    assert result.events[0].direction is Direction.FROM_DEVICE
    start = next(c for c in result.commands if c.cmd == "MUTATION StartContainer")
    assert start.transport is TransportType.GRAPHQL
    assert start.document and start.document.startswith("mutation StartContainer(")
    assert [(f.name, f.kind, f.required) for f in start.request_fields] == [
        ("id", FieldKind.STRING, True),
        ("force", FieldKind.BOOLEAN, False),
    ]


def test_typed_state_from_nested_data_classes(tmp_path: Path) -> None:
    result = scan(_app(tmp_path), "com.example.nas")
    assert result is not None

    assert result.poll_queries == ["QUERY GetMetrics"]
    assert result.state[0].name == "metrics_cpu_percent_total"  # identifier; wire path stays dotted
    assert [(f.serialized_name, f.kind, f.nullable) for f in result.state] == [
        ("metrics.cpu.percentTotal", FieldKind.NUMBER, False),
        ("metrics.memory.buffcache", FieldKind.INTEGER, True),
        ("metrics.memory.total", FieldKind.INTEGER, False),
        ("metrics.os.hostname", FieldKind.STRING, False),  # JADX's f5014os → os
    ]  # lists (disks) aren't state


def test_path_and_api_key_found_in_obfuscated_code(tmp_path: Path) -> None:
    result = scan(_app(tmp_path), "com.example.nas")
    assert result is not None

    assert result.path == "/graphql"
    assert result.auth.type is AuthType.API_KEY
    assert [f.name for f in result.auth.fields] == ["x-api-key"]


def test_no_apollo_classes_no_result(tmp_path: Path) -> None:
    (tmp_path / "sources" / "com" / "example").mkdir(parents=True)

    assert scan(tmp_path, "com.example") is None
