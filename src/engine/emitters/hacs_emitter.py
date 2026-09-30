# SPDX-License-Identifier: MIT
"""P5 — HACS integration emitter: renders the custom_components package."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

_LOGGER = logging.getLogger(__name__)
_TEMPLATES_DIR = Path(__file__).parents[1] / "templates" / "hacs"
_TESTS_TEMPLATES_DIR = Path(__file__).parents[1] / "templates" / "hacs_tests"


def emit_tests(ctx: dict[str, Any], out_root: Path) -> Path | None:
    """Render runtime tests into *out_root*/tests/ (run by V-3 in the sandbox).

    Returns the tests dir, or None when the integration has no push-state entity
    to probe or uses a transport the mock device can't speak (BLE).
    """
    if ctx.get("has_challenge_auth"):
        tests_dir = out_root / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        env = _env(_TESTS_TEMPLATES_DIR)
        _render(env, ctx, out_root, "pytest.ini.j2", "pytest.ini")
        _render(env, ctx, tests_dir, "__init__.py.j2", "__init__.py")
        _render(env, ctx, tests_dir, "conftest_ble_auth.py.j2", "conftest.py")
        _render(env, ctx, tests_dir, "test_integration_ble_auth.py.j2", "test_integration.py")
        _fix_imports(tests_dir, select="I001,F401")
        return tests_dir

    probe = _test_probe(ctx)
    if probe is None or ctx.get("has_ble"):
        _LOGGER.info("No runtime tests emitted for %s (no probe entity or BLE)", ctx["domain"])
        return None

    env = Environment(
        loader=FileSystemLoader(str(_TESTS_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    tests_ctx = {
        **ctx,
        "test_probe": probe,
        "test_initial_state": {probe["key"]: probe["initial_value"]},
        "test_switch": _test_switch(ctx),
        "test_select": _test_select(ctx),
        "test_press": next((b for b in ctx.get("buttons", []) if not b["maintenance"]), None),
        "test_maintenance": [b for b in ctx.get("buttons", []) if b["maintenance"]],
        "test_number": ctx["numbers"][0] if ctx.get("numbers") else None,
    }
    tests_dir = out_root / "tests"
    tests_dir.mkdir(parents=True, exist_ok=True)
    _render(env, tests_ctx, out_root, "pytest.ini.j2", "pytest.ini")
    # WebSocket push devices and polled HTTP devices get different mocks and tests.
    suffix = "_http" if ctx.get("transport") == "http_rest" else ""
    _render(env, tests_ctx, tests_dir, "__init__.py.j2", "__init__.py")
    for name in ("conftest", "test_integration"):
        _render(env, tests_ctx, tests_dir, f"{name}{suffix}.py.j2", f"{name}.py")
    # Test-only helpers are imported unconditionally; drop the ones this device doesn't use.
    _fix_imports(tests_dir, select="I001,F401")
    return tests_dir


def _test_switch(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Prefer a state-backed switch (with the wire key the device pushes), else any."""
    switches = ctx.get("switches", [])
    state_keys = {
        s["attr"]: s["key"]
        for s in ctx.get("model_sensors", []) + ctx.get("model_binary_sensors", [])
    }
    for sw in switches:
        if sw["state_attr"] in state_keys:
            return {**sw, "state_key": state_keys[sw["state_attr"]]}
    return {**switches[0], "state_key": None} if switches else None


def _test_select(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """A state-backed mode select plus the pushed key/value that selects its 2nd option."""
    mode_actions: dict[int, str] = ctx.get("mode_actions") or {}
    for sel in ctx.get("selects", []):
        state_key = next(
            (s["key"] for s in ctx.get("model_sensors", []) if s["attr"] == sel["state_attr"]),
            None,
        )
        if state_key and len(mode_actions) >= 2:
            (_, first), (value, name) = sorted(mode_actions.items())[:2]
            return {
                **sel,
                "state_key": state_key,
                "push_value": value,
                "push_option": name,
                "pick_option": first,
            }
    return None


def _test_probe(ctx: dict[str, Any]) -> dict[str, Any] | None:
    """Pick one state-backed entity whose value the runtime tests drive and observe."""
    if ctx.get("sensors"):
        spec = ctx["sensors"][0]
        return {
            "platform": "sensor",
            "key": spec["key"],
            "initial_value": 1,
            "initial_state": "1",
            "next_value": 2,
            "next_state": "2",
        }
    if ctx.get("binary_sensors"):
        spec = ctx["binary_sensors"][0]
        return {
            "platform": "binary_sensor",
            "key": spec["key"],
            "initial_value": True,
            "initial_state": "on",
            "next_value": False,
            "next_state": "off",
        }
    return None


def emit(ctx: dict[str, Any], out_root: Path) -> Path:
    """Render HACS integration into *out_root*/custom_components/{domain}/."""
    domain_dir = out_root / "custom_components" / str(ctx["domain"])
    domain_dir.mkdir(parents=True, exist_ok=True)
    (domain_dir / "translations").mkdir(exist_ok=True)
    if ctx.get("has_challenge_auth"):
        return _emit_ble_auth(ctx, out_root, domain_dir)

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )

    _render(env, ctx, domain_dir, "manifest.json.j2", "manifest.json")
    sort_manifest(domain_dir / "manifest.json")
    _render(env, ctx, domain_dir, "__init__.py.j2", "__init__.py")
    _render(env, ctx, domain_dir, "const.py.j2", "const.py")
    _render(env, ctx, domain_dir, "config_flow.py.j2", "config_flow.py")
    coordinator = (
        "coordinator_http.py.j2" if ctx.get("transport") == "http_rest" else "coordinator.py.j2"
    )
    _render(env, ctx, domain_dir, coordinator, "coordinator.py")
    if ctx.get("has_ble"):
        _render(env, ctx, domain_dir, "ble_coordinator.py.j2", "ble_coordinator.py")
    _render(env, ctx, domain_dir, "entity_base.py.j2", "entity_base.py")
    _render(env, ctx, domain_dir, "strings.json.j2", "strings.json")
    _render(env, ctx, domain_dir / "translations", "translations/en.json.j2", "en.json")

    platforms = ctx["platforms"]
    if "sensor" in platforms:
        _render(env, ctx, domain_dir, "sensor.py.j2", "sensor.py")
    if "binary_sensor" in platforms:
        _render(env, ctx, domain_dir, "binary_sensor.py.j2", "binary_sensor.py")
    if "switch" in platforms:
        _render(env, ctx, domain_dir, "switch.py.j2", "switch.py")
    if "button" in platforms:
        _render(env, ctx, domain_dir, "button.py.j2", "button.py")
    if "select" in platforms:
        _render(env, ctx, domain_dir, "select.py.j2", "select.py")
    if "number" in platforms:
        _render(env, ctx, domain_dir, "number.py.j2", "number.py")
    if ctx.get("has_camera"):
        _render(env, ctx, domain_dir, "camera.py.j2", "camera.py")

    # HACS repo metadata: the minimum HA version lives here, not in manifest.json
    # (hassfest rejects a "homeassistant" key in custom integration manifests).
    _render(env, ctx, out_root, "hacs.json.j2", "hacs.json")

    _fix_imports(domain_dir)
    _LOGGER.info("HACS integration emitted to %s", domain_dir)
    return domain_dir


def _emit_ble_auth(ctx: dict[str, Any], out_root: Path, domain_dir: Path) -> Path:
    """BLE device with challenge-response auth: enrolment flow + authenticated button."""
    env = _env(_TEMPLATES_DIR / "ble_auth")
    for template, target in [
        ("manifest.json.j2", domain_dir / "manifest.json"),
        ("__init__.py.j2", domain_dir / "__init__.py"),
        ("const.py.j2", domain_dir / "const.py"),
        ("config_flow.py.j2", domain_dir / "config_flow.py"),
        ("button.py.j2", domain_dir / "button.py"),
        ("diagnostics.py.j2", domain_dir / "diagnostics.py"),
        ("strings.json.j2", domain_dir / "strings.json"),
        ("strings.json.j2", domain_dir / "translations" / "en.json"),
    ]:
        _render(env, ctx, target.parent, template, target.name)
    sort_manifest(domain_dir / "manifest.json")
    _render(_env(_TEMPLATES_DIR), ctx, out_root, "hacs.json.j2", "hacs.json")
    _fix_imports(domain_dir)
    _LOGGER.info("HACS integration (BLE challenge-response) emitted to %s", domain_dir)
    return domain_dir


def _env(templates: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(templates)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def sort_manifest(path: Path) -> bool:
    """Order manifest keys as hassfest requires: domain, name, then alphabetical.

    Returns True if the file changed.
    """
    data = json.loads(path.read_text())
    head = {k: data[k] for k in ("domain", "name") if k in data}
    ordered = head | {k: data[k] for k in sorted(data) if k not in head}
    text = json.dumps(ordered, indent=2, ensure_ascii=False) + "\n"
    if text == path.read_text():
        return False
    path.write_text(text)
    return True


def _fix_imports(directory: Path, select: str = "I001") -> None:
    """Run ruff --fix to sort (and optionally prune) imports in emitted Python files."""
    try:
        subprocess.run(
            ["ruff", "check", "--select", select, "--fix", str(directory)],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        _LOGGER.debug("ruff not found; skipping import sort")


def _render(
    env: Environment, ctx: dict[str, Any], out_dir: Path, template: str, filename: str
) -> None:
    rendered = env.get_template(template).render(**ctx)
    (out_dir / filename).write_text(rendered)
