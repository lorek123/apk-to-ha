# SPDX-License-Identifier: MIT
"""V-2 — hassfest validation.

Two tiers:
  1. Fast structural check (always runs, no HA Core needed).
  2. Real hassfest via HA Core clone or Docker (when available).

Returns a HassfestResult with a list of findings.
"""
from __future__ import annotations

import ast
import asyncio
import json
import logging
import shutil
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

_LOGGER = logging.getLogger(__name__)

_HA_CORE_DIR = Path(__file__).parents[3] / ".cache" / "ha-core"
_HA_TARGET = Path(__file__).parents[3] / "config" / "ha_target.toml"

_REQUIRED_MANIFEST_KEYS = {
    "domain", "name", "codeowners", "config_flow", "documentation",
    "homeassistant", "iot_class", "quality_scale", "requirements", "version",
}
_VALID_IOT_CLASSES = {
    "assumed_state", "cloud_polling", "cloud_push",
    "local_polling", "local_push", "calculated",
}
_VALID_QUALITY_SCALES = {"internal", "silver", "gold", "platinum"}

# Platinum requirements
_PLATINUM_ENTITY_REQS = {"_attr_has_entity_name", "_attr_unique_id"}


@dataclass
class Finding:
    severity: str      # "error" | "warning"
    check: str         # which check produced this
    message: str


@dataclass
class HassfestResult:
    passed: bool
    tier: str          # "structural" | "hassfest_local" | "hassfest_docker" | "skipped"
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

    structural_ok = not any(f.severity == "error" for f in findings)

    # Attempt real hassfest if structural pass looks clean enough
    real_result = await _try_real_hassfest(integration_dir)
    if real_result is not None:
        rc, output, tier = real_result
        if rc:  # non-zero → parse output for error details
            for line in output.splitlines():
                if any(kw in line for kw in ("ERROR", "Invalid", "failed")):
                    findings.append(Finding("error", "hassfest", line.strip()))
        _LOGGER.debug("hassfest raw output (rc=%d):\n%s", rc, output[:2000])

    tier_name = real_result[2] if real_result is not None else "structural"
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
            findings.append(Finding("error", "manifest", f"manifest.json missing required key: {key!r}"))

    if data.get("iot_class") not in _VALID_IOT_CLASSES:
        findings.append(Finding("error", "manifest",
                                f"iot_class {data.get('iot_class')!r} not in {sorted(_VALID_IOT_CLASSES)}"))

    if data.get("quality_scale") not in _VALID_QUALITY_SCALES:
        findings.append(Finding("warning", "manifest",
                                f"quality_scale {data.get('quality_scale')!r} unrecognised"))

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
    data = json.loads(mf.read_text())
    domain = data.get("domain", "")

    platform_files = {
        "sensor", "binary_sensor", "switch", "button", "select", "number",
        "light", "cover", "media_player", "climate", "fan", "lock",
    }
    for py_file in d.glob("*.py"):
        name = py_file.stem
        if name not in platform_files:
            continue
        src = py_file.read_text()
        if "async def async_setup_entry" not in src:
            findings.append(Finding("error", "platforms",
                                    f"{name}.py missing async_setup_entry"))


def _check_config_flow(d: Path, findings: list[Finding]) -> None:
    cf = d / "config_flow.py"
    if not cf.exists():
        findings.append(Finding("error", "config_flow", "config_flow.py missing"))
        return

    src = cf.read_text()
    if "ConfigFlow" not in src:
        findings.append(Finding("error", "config_flow", "No ConfigFlow subclass found"))
    if "domain=" not in src:
        findings.append(Finding("error", "config_flow",
                                "ConfigFlow class missing domain= keyword arg"))
    if "async_step_user" not in src:
        findings.append(Finding("error", "config_flow",
                                "ConfigFlow missing async_step_user"))


def _check_spdx(d: Path, findings: list[Finding]) -> None:
    for py in d.rglob("*.py"):
        first_line = py.read_text().splitlines()[0] if py.read_text() else ""
        if "SPDX-License-Identifier" not in first_line:
            findings.append(Finding("error", "spdx",
                                    f"{py.relative_to(d)}: missing SPDX header"))


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
        uses_base = base.exists() and (
            "entity_base" in src or "Entity(" in src
        )
        for req in _PLATINUM_ENTITY_REQS:
            if req in src:
                continue
            if uses_base and req in satisfied_in_base:
                continue
            findings.append(Finding("warning", "platinum",
                                    f"{py.name}: entity missing {req}"))


# ── real hassfest (best-effort) ───────────────────────────────────────────────

async def _try_real_hassfest(int_path: Path) -> tuple[int, str, str] | None:
    """Try HA Core clone, then Docker. Returns (rc, output, tier) or None."""
    if _HA_CORE_DIR.exists():
        _LOGGER.info("Running hassfest via HA Core clone at %s", _HA_CORE_DIR)
        with open(_HA_TARGET, "rb") as fh:
            cfg = tomllib.load(fh)
        python = shutil.which("python3") or "python3"
        rc, out = await _run(
            [python, "-m", "script.hassfest",
             "--integration-path", str(int_path), "--action", "validate"],
            cwd=_HA_CORE_DIR,
        )
        return rc, out, "hassfest_local"

    if shutil.which("docker"):
        with open(_HA_TARGET, "rb") as fh:
            cfg = tomllib.load(fh)
        tag = cfg["docker"]["ha_image_tag"]
        _LOGGER.info("Running hassfest via Docker image %s", tag)
        rc, out = await _run([
            "docker", "run", "--rm",
            "-v", f"{int_path}:/tmp/integration:ro",
            f"homeassistant/home-assistant:{tag}",
            "python3", "-m", "script.hassfest",
            "--integration-path", "/tmp/integration",
            "--action", "validate",
        ])
        return rc, out, "hassfest_docker"

    _LOGGER.info("Neither HA Core clone nor Docker found — structural check only")
    return None


async def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=cwd,
    )
    stdout, _ = await proc.communicate()
    return proc.returncode or 0, stdout.decode()
