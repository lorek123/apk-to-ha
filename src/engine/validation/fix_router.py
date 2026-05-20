# SPDX-License-Identifier: MIT
"""V-5 — Fix router.

Routes V-1/V-2 findings to the specific emitter phase that produced the
offending file and applies a deterministic fix. Only deterministic strategies
are implemented here; findings that require semantic reasoning are marked
``skipped`` and surface to the human operator.

Strategies (cheapest first):
  ruff_fix          — run `ruff --fix` on the integration directory
  spdx_prepend      — prepend missing SPDX header to a Python file
  manifest_patch    — update a key in manifest.json using the known ctx value
  template_rerender — re-render one HACS template with (optionally patched) ctx
"""
from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .hassfest import Finding
from .ruff_check import RuffFinding

_LOGGER = logging.getLogger(__name__)
_HACS_TEMPLATES = Path(__file__).parents[1] / "templates" / "hacs"

# Ruff codes that `ruff --fix` handles automatically
_RUFF_AUTO_FIXABLE = frozenset({"I001", "I002", "F401", "W291", "W292", "W293", "UP"})

# Output filename → HACS template name
_FILE_TO_TEMPLATE: dict[str, str] = {
    "__init__.py": "__init__.py.j2",
    "coordinator.py": "coordinator.py.j2",
    "config_flow.py": "config_flow.py.j2",
    "sensor.py": "sensor.py.j2",
    "binary_sensor.py": "binary_sensor.py.j2",
    "switch.py": "switch.py.j2",
    "button.py": "button.py.j2",
    "select.py": "select.py.j2",
    "number.py": "number.py.j2",
    "entity_base.py": "entity_base.py.j2",
    "const.py": "const.py.j2",
}

# Manifest keys that can be inferred from ctx
_MANIFEST_CTX_KEYS = {"iot_class", "version", "ha_min_version", "quality_scale"}


@dataclass
class FixResult:
    applied: int
    skipped: int
    details: list[str] = field(default_factory=list)


def route_and_apply(
    ruff_findings: list[RuffFinding],
    hassfest_findings: list[Finding],
    ctx: dict[str, Any],
    integration_dir: Path,
) -> FixResult:
    """Apply deterministic fixes for *findings*. Returns counts."""
    applied = 0
    skipped = 0
    details: list[str] = []

    # ── V-1: ruff ─────────────────────────────────────────────────────────────
    fixable_ruff = [f for f in ruff_findings if _is_ruff_fixable(f.code)]
    unfixable_ruff = [f for f in ruff_findings if not _is_ruff_fixable(f.code)]

    if fixable_ruff:
        n = _apply_ruff_fix(integration_dir)
        applied += n
        details.append(f"ruff --fix: {n} fix(es) applied")

    skipped += len(unfixable_ruff)
    for f in unfixable_ruff:
        _LOGGER.warning("fix_router: no auto-fix for ruff [%s] %s:%d", f.code, Path(f.file).name, f.line)

    # ── V-2: hassfest ─────────────────────────────────────────────────────────
    for finding in hassfest_findings:
        if finding.severity == "warning":
            continue  # warnings don't block; skip for now

        result = _fix_hassfest(finding, ctx, integration_dir)
        if result:
            applied += 1
            details.append(result)
        else:
            skipped += 1
            _LOGGER.warning(
                "fix_router: no deterministic fix for [%s] %s",
                finding.check, finding.message,
            )

    return FixResult(applied=applied, skipped=skipped, details=details)


# ── internal helpers ──────────────────────────────────────────────────────────

def _is_ruff_fixable(code: str) -> bool:
    return any(code.startswith(prefix) for prefix in _RUFF_AUTO_FIXABLE)


def _fix_hassfest(finding: Finding, ctx: dict[str, Any], d: Path) -> str | None:
    """Return a short description if a fix was applied, else None."""
    msg = finding.message

    if finding.check == "spdx":
        file_rel = msg.split(":")[0].strip()
        target = d / file_rel
        if target.exists() and _prepend_spdx(target):
            return f"spdx: prepended header to {file_rel}"
        return None

    if finding.check == "manifest":
        if "iot_class" in msg and "not in" in msg:
            val = ctx.get("iot_class", "local_polling")
            _patch_manifest(d, "iot_class", val)
            return f"manifest: patched iot_class → {val!r}"

        if "missing required key" in msg:
            try:
                key = msg.split("'")[1]
            except IndexError:
                return None
            if key not in _MANIFEST_CTX_KEYS:
                return None
            # Map manifest key to ctx key (version lives as integration_version in ctx)
            ctx_key = "integration_version" if key == "version" else key
            val = ctx.get(ctx_key)
            if val is None:
                return None
            _patch_manifest(d, key, val)
            return f"manifest: patched missing key {key!r} → {val!r}"

        if "invalid JSON" in msg:
            # Can't auto-fix corrupted JSON — needs template rerender
            tmpl = "__init__.py.j2"  # not applicable, but at least rerender manifest
            _rerender_manifest(d, ctx)
            return "manifest: re-rendered manifest.json from template"

        return None

    if finding.check == "config_flow":
        _rerender_file("config_flow.py", d, ctx)
        return "template_rerender: config_flow.py"

    if finding.check == "platforms" and "async_setup_entry" in msg:
        filename = msg.split()[0]
        if filename in _FILE_TO_TEMPLATE:
            _rerender_file(filename, d, ctx)
            return f"template_rerender: {filename}"
        return None

    return None


def _apply_ruff_fix(directory: Path) -> int:
    result = subprocess.run(
        ["ruff", "check", "--select", "E,F,W,I", "--ignore", "E501", "--fix", str(directory)],
        capture_output=True,
        text=True,
        check=False,
    )
    # "Fixed N errors." appears in stderr on some ruff versions, stdout on others
    for line in (result.stdout + result.stderr).splitlines():
        if "Fixed" in line:
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                pass
    return 1 if result.returncode in (0, 1) else 0


def _prepend_spdx(path: Path) -> bool:
    content = path.read_text()
    if "SPDX-License-Identifier" in content:
        return False
    path.write_text("# SPDX-License-Identifier: MIT\n" + content)
    return True


def _patch_manifest(d: Path, key: str, value: Any) -> None:
    mf = d / "manifest.json"
    data = json.loads(mf.read_text())
    data[key] = value
    mf.write_text(json.dumps(data, indent=2) + "\n")


def _rerender_manifest(d: Path, ctx: dict[str, Any]) -> None:
    env = _jinja_env()
    rendered = env.get_template("manifest.json.j2").render(**ctx)
    (d / "manifest.json").write_text(rendered)


def _rerender_file(filename: str, d: Path, ctx: dict[str, Any]) -> None:
    template_name = _FILE_TO_TEMPLATE.get(filename)
    if template_name is None:
        _LOGGER.warning("fix_router: no template mapped for %s", filename)
        return
    env = _jinja_env()
    rendered = env.get_template(template_name).render(**ctx)
    (d / filename).write_text(rendered)


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_HACS_TEMPLATES)),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
