# SPDX-License-Identifier: MIT
"""V-2 — hassfest validation.

Two tiers:
  1. Fast structural check (always runs, no HA Core needed).
  2. Real hassfest via the official ghcr.io/home-assistant/hassfest image at the
     pinned HA tag (when Docker is available).

Returns a HassfestResult with a list of findings.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_LOGGER = logging.getLogger(__name__)

_HA_TARGET = Path(__file__).parents[3] / "config" / "ha_target.toml"
_HASSFEST_IMAGE = "ghcr.io/home-assistant/hassfest"

_REQUIRED_MANIFEST_KEYS = {
    "domain",
    "name",
    "codeowners",
    "config_flow",
    "documentation",
    "iot_class",
    "quality_scale",
    "requirements",
    "version",
}
_VALID_IOT_CLASSES = {
    "assumed_state",
    "cloud_polling",
    "cloud_push",
    "local_polling",
    "local_push",
    "calculated",
}
_VALID_QUALITY_SCALES = {"internal", "silver", "gold", "platinum"}

# Platinum requirements
_PLATINUM_ENTITY_REQS = {"_attr_has_entity_name", "_attr_unique_id"}


@dataclass
class Finding:
    severity: str  # "error" | "warning"
    check: str  # which check produced this
    message: str


@dataclass
class HassfestResult:
    passed: bool
    tier: str  # "structural" (hassfest couldn't run) | "hassfest_docker"
    findings: list[Finding] = field(default_factory=list)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warning"]


async def validate(integration_dir: Path) -> HassfestResult:
    """Run validation on *integration_dir* (the custom_components/{domain}/ folder)."""
    findings: list[Finding] = []

    _check_manifest(integration_dir, findings)
    _check_platforms(integration_dir, findings)
    _check_config_flow(integration_dir, findings)
    _check_spdx(integration_dir, findings)
    _check_platinum(integration_dir, findings)

    # Real hassfest (official image) on top of the structural checks
    real = await _run_real_hassfest(integration_dir)
    if real is None:
        tier_name = "structural"
    else:
        tier_name = "hassfest_docker"
        findings.extend(real)

    passed = not any(f.severity == "error" for f in findings)
    return HassfestResult(passed=passed, tier=tier_name, findings=findings)


# ── structural checks ─────────────────────────────────────────────────────────


def _check_manifest(d: Path, findings: list[Finding]) -> None:
    mf = d / "manifest.json"
    if not mf.exists():
        findings.append(Finding("error", "manifest", "manifest.json missing"))
        return

    try:
        data = json.loads(mf.read_text())
    except json.JSONDecodeError as exc:
        findings.append(Finding("error", "manifest", f"manifest.json invalid JSON: {exc}"))
        return

    for key in _REQUIRED_MANIFEST_KEYS:
        if key not in data:
            findings.append(
                Finding("error", "manifest", f"manifest.json missing required key: {key!r}")
            )

    if data.get("iot_class") not in _VALID_IOT_CLASSES:
        findings.append(
            Finding(
                "error",
                "manifest",
                f"iot_class {data.get('iot_class')!r} not in {sorted(_VALID_IOT_CLASSES)}",
            )
        )

    if data.get("quality_scale") not in _VALID_QUALITY_SCALES:
        findings.append(
            Finding(
                "warning", "manifest", f"quality_scale {data.get('quality_scale')!r} unrecognised"
            )
        )

    if not isinstance(data.get("version"), str):
        findings.append(Finding("error", "manifest", "manifest.json version must be a string"))

    # translations must exist
    if not (d / "translations" / "en.json").exists():
        findings.append(Finding("error", "manifest", "translations/en.json missing"))
    if not (d / "strings.json").exists():
        findings.append(Finding("warning", "manifest", "strings.json missing"))


def _check_platforms(d: Path, findings: list[Finding]) -> None:
    mf = d / "manifest.json"
    if not mf.exists():
        return

    platform_files = {
        "sensor",
        "binary_sensor",
        "switch",
        "button",
        "select",
        "number",
        "light",
        "cover",
        "media_player",
        "climate",
        "fan",
        "lock",
    }
    for py_file in d.glob("*.py"):
        name = py_file.stem
        if name not in platform_files:
            continue
        src = py_file.read_text()
        if "async def async_setup_entry" not in src:
            findings.append(Finding("error", "platforms", f"{name}.py missing async_setup_entry"))


def _check_config_flow(d: Path, findings: list[Finding]) -> None:
    cf = d / "config_flow.py"
    if not cf.exists():
        findings.append(Finding("error", "config_flow", "config_flow.py missing"))
        return

    src = cf.read_text()
    if "ConfigFlow" not in src:
        findings.append(Finding("error", "config_flow", "No ConfigFlow subclass found"))
    if "domain=" not in src:
        findings.append(
            Finding("error", "config_flow", "ConfigFlow class missing domain= keyword arg")
        )
    if "async_step_user" not in src:
        findings.append(Finding("error", "config_flow", "ConfigFlow missing async_step_user"))


def _check_spdx(d: Path, findings: list[Finding]) -> None:
    for py in d.rglob("*.py"):
        first_line = py.read_text().splitlines()[0] if py.read_text() else ""
        if "SPDX-License-Identifier" not in first_line:
            findings.append(Finding("error", "spdx", f"{py.relative_to(d)}: missing SPDX header"))


def _check_platinum(d: Path, findings: list[Finding]) -> None:
    """Spot-check platinum requirements.

    If entity_base.py defines the platinum attributes (shared base class pattern),
    all platform files that import from it are considered compliant.
    """
    # Check whether attributes are satisfied via a shared base class
    base = d / "entity_base.py"
    base_src = base.read_text() if base.exists() else ""
    satisfied_in_base = {req for req in _PLATINUM_ENTITY_REQS if req in base_src}

    platform_files = {"sensor", "binary_sensor", "switch", "button", "select", "number"}
    for py in d.glob("*.py"):
        if py.stem not in platform_files:
            continue
        src = py.read_text()
        uses_base = base.exists() and ("entity_base" in src or "Entity(" in src)
        for req in _PLATINUM_ENTITY_REQS:
            if req in src:
                continue
            if uses_base and req in satisfied_in_base:
                continue
            findings.append(Finding("warning", "platinum", f"{py.name}: entity missing {req}"))


# ── real hassfest (official image) ─────────────────────────────────────────────

# `* [ERROR] [MANIFEST] Invalid manifest: ...` — one line per hassfest finding
_HASSFEST_LINE = re.compile(r"^\* \[(ERROR|WARNING)\] \[([A-Z_]+)\] (.+)$")
_HASSFEST_TIMEOUT = 300


def _load_ha_target() -> dict[str, Any]:
    with open(_HA_TARGET, "rb") as fh:
        return tomllib.load(fh)


def parse_hassfest_output(output: str) -> list[Finding] | None:
    """Findings from hassfest's report, or None if the output isn't a hassfest report."""
    if "Integrations:" not in output:
        return None
    findings: list[Finding] = []
    for line in output.splitlines():
        m = _HASSFEST_LINE.match(line.strip())
        if m:
            severity, plugin, message = m.groups()
            findings.append(Finding(severity.lower(), f"hassfest:{plugin.lower()}", message))
    return findings


async def _run_real_hassfest(int_path: Path) -> list[Finding] | None:
    """Run ghcr.io/home-assistant/hassfest at the pinned HA tag.

    Returns its findings, or None when it could not run (no Docker, image pull or
    tool failure) — the caller then reports tier "structural", never a real pass.
    """
    if not shutil.which("docker"):
        _LOGGER.info("Docker not found — hassfest skipped, structural checks only")
        return None
    cfg = await asyncio.to_thread(_load_ha_target)
    docker_cfg = cfg["docker"]
    image = f"{docker_cfg.get('hassfest_image', _HASSFEST_IMAGE)}:{docker_cfg['ha_image_tag']}"
    mount = await asyncio.to_thread(int_path.resolve)
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        f"{mount}:/github/workspace/custom_components/{int_path.name}:ro",
        image,
    ]
    _LOGGER.info("Running hassfest (%s) on %s", image, int_path.name)
    try:
        rc, output = await asyncio.wait_for(_run(cmd), timeout=_HASSFEST_TIMEOUT)
    except TimeoutError:
        _LOGGER.warning("hassfest timed out after %ds — structural checks only", _HASSFEST_TIMEOUT)
        return None
    findings = parse_hassfest_output(output)
    if findings is None:
        _LOGGER.warning("hassfest did not run (rc=%d): %s", rc, output.strip()[-500:])
        return None
    if rc and not any(f.severity == "error" for f in findings):
        findings.append(Finding("error", "hassfest", f"hassfest failed (rc={rc})"))
    return findings


async def _run(cmd: list[str]) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await proc.communicate()
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode or 0, stdout.decode(errors="replace")
