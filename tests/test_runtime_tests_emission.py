# SPDX-License-Identifier: MIT
"""Tests for V-3 runtime-test emission and container_test mode selection."""

from __future__ import annotations

import py_compile
import subprocess
from pathlib import Path
from typing import Any

import pytest

from engine.emitters import context as ctx_mod
from engine.emitters import hacs_emitter
from engine.ir.models import (
    AuthScheme,
    AuthType,
    DiscoveryMechanism,
    DiscoveryType,
    EntityHint,
    FieldDef,
    FieldKind,
    Framework,
    ProtocolIR,
    StateSchema,
    TransportContract,
    TransportType,
)
from engine.validation import container_test


def _ctx(fields: list[FieldDef], transport: TransportType = TransportType.WEBSOCKET) -> Any:
    ir = ProtocolIR(
        apk_path="/tmp/test.apk",
        package_name="com.example.device",
        app_name="My Device",
        version_name="1.0.0",
        framework=Framework.NATIVE,
        transport=TransportContract(type=transport, port=8887),
        discovery=DiscoveryMechanism(type=DiscoveryType.NONE),
        auth=AuthScheme(type=AuthType.HANDSHAKE, handshake_cmd="hello"),
        state=StateSchema(push_cmd="state", fields=fields),
    )
    return ctx_mod.build(ir)


_BATTERY = FieldDef(name="battery", kind=FieldKind.INTEGER, entity_hint=EntityHint.SENSOR)
_CHARGING = FieldDef(name="charging", kind=FieldKind.BOOLEAN, entity_hint=EntityHint.BINARY_SENSOR)


def test_emits_compilable_lint_clean_tests(tmp_path: Path) -> None:
    tests_dir = hacs_emitter.emit_tests(_ctx([_BATTERY]), tmp_path)

    assert tests_dir == tmp_path / "tests"
    assert (tmp_path / "pytest.ini").read_text().startswith("# SPDX-License-Identifier: MIT")
    for name in ("__init__.py", "conftest.py", "test_integration.py"):
        path = tests_dir / name
        assert path.read_text().startswith("# SPDX-License-Identifier: MIT")
        py_compile.compile(str(path), doraise=True)
    ruff = subprocess.run(
        ["ruff", "check", "--select", "E,F,W,I", "--ignore", "E501", str(tests_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ruff.returncode == 0, ruff.stdout


def test_protocol_constants_come_from_ir(tmp_path: Path) -> None:
    tests_dir = hacs_emitter.emit_tests(_ctx([_BATTERY]), tmp_path)
    assert tests_dir is not None

    conftest = (tests_dir / "conftest.py").read_text()
    assert 'AUTH_CMD = "hello"' in conftest
    assert 'STATE_CMD = "state"' in conftest
    assert 'PROBE_KEY = "battery"' in (tests_dir / "test_integration.py").read_text()


def test_binary_sensor_probe_when_no_sensors(tmp_path: Path) -> None:
    tests_dir = hacs_emitter.emit_tests(_ctx([_CHARGING]), tmp_path)
    assert tests_dir is not None

    body = (tests_dir / "test_integration.py").read_text()
    assert 'PROBE_PLATFORM = "binary_sensor"' in body
    assert '== "on"' in body


def test_no_tests_without_a_probe_entity(tmp_path: Path) -> None:
    assert hacs_emitter.emit_tests(_ctx([]), tmp_path) is None
    assert not (tmp_path / "tests").exists()


# ── container_test mode selection ─────────────────────────────────────────────

_CFG = {
    "docker": {"ha_image": "homeassistant/home-assistant", "ha_image_tag": "2026.5.2"},
    "sandbox": {"image": "hacs-engine-sandbox", "tag": "latest", "phcc_version": "0.13.331"},
}


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("0.13.331", ("hacs-engine-sandbox:latest", "runtime")),
        ("0.13.300", ("homeassistant/home-assistant:2026.5.2", "import")),  # stale sandbox
        (None, ("homeassistant/home-assistant:2026.5.2", "import")),  # not built
    ],
)
def test_resolve_image_requires_matching_phcc(
    monkeypatch: pytest.MonkeyPatch, label: str | None, expected: tuple[str, str]
) -> None:
    monkeypatch.setattr(container_test, "_image_label", lambda image, key: label)

    assert container_test._resolve_image(_CFG) == expected


async def test_skipped_without_docker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("engine.validation.container_test.shutil.which", lambda name: None)

    result = await container_test.run("mydevice", tmp_path)

    assert (result.ran, result.passed, result.mode) == (False, None, "skipped")
