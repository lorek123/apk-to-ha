# SPDX-License-Identifier: MIT
"""P2-2 — Payload class resolver.

For each Java class name (typically the @Body or return type of a Retrofit method),
find its definition in the decompiled source tree and extract typed field descriptors
from @SerializedName (Gson) and @Json(name=...) (Moshi) annotations.

Handles:
  - @SerializedName("wire_name") → FieldDef with serialized_name set
  - @Json(name = "wire_name")    → same
  - Primitive Java types → FieldKind mapping
  - Collections (List<T>, ArrayList<T>) → FieldKind.ARRAY
  - Nested classes (resolved shallowly — 1 level deep)
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..ir.models import FieldDef, FieldKind, PayloadSchema

_LOGGER = logging.getLogger(__name__)

# ── patterns ──────────────────────────────────────────────────────────────────

# @SerializedName("wire_name") followed by optional other annotations, then the field
_SERIALIZED_NAME_RE = re.compile(
    r'@SerializedName\s*\(\s*"([^"]+)"\s*\)'
    r'(?:\s*@[\w.]+(?:\([^)]*\))?\s*)*'     # other annotations
    r'\s*(?:public|private|protected)?\s*'
    r'(?:static\s+)?(?:final\s+)?'
    r'([\w.<>, ]+?)\s+(\w+)\s*[;=]',
    re.DOTALL,
)

# @Json(name = "wire_name") — Moshi
_JSON_NAME_RE = re.compile(
    r'@Json\s*\(\s*name\s*=\s*"([^"]+)"\s*\)'
    r'(?:\s*@[\w.]+(?:\([^)]*\))?\s*)*'
    r'\s*(?:public|private|protected)?\s*'
    r'(?:static\s+)?(?:final\s+)?'
    r'([\w.<>, ]+?)\s+(\w+)\s*[;=]',
    re.DOTALL,
)

# Collection wrappers that indicate ARRAY kind
_COLLECTION_RE = re.compile(
    r'\b(?:List|ArrayList|LinkedList|Set|Collection|Array)\s*<'
)

# Nullable markers
_NULLABLE_RE = re.compile(r'@(?:Nullable|Null)\b')


# ── resolver ──────────────────────────────────────────────────────────────────


class PayloadResolver:
    """Resolves a Java type name to its wire-name FieldDef list."""

    def __init__(self, apk_out_dir: Path) -> None:
        self._sources = apk_out_dir / "sources"
        self._cache: dict[str, list[FieldDef]] = {}

    def resolve(self, type_name: str) -> PayloadSchema:
        """Return a PayloadSchema for *type_name*; fields=[] if class not found."""
        is_collection = False
        # Unwrap List<T> / ArrayList<T>
        col_m = re.match(r'(?:List|ArrayList|LinkedList|Set|Collection)<(\w+)>', type_name)
        if col_m:
            type_name = col_m.group(1)
            is_collection = True

        if type_name in self._cache:
            return PayloadSchema(
                class_name=type_name,
                fields=self._cache[type_name],
                is_collection=is_collection,
            )

        fields = self._extract_fields(type_name)
        self._cache[type_name] = fields
        return PayloadSchema(
            class_name=type_name,
            fields=fields,
            is_collection=is_collection,
        )

    def _extract_fields(self, type_name: str) -> list[FieldDef]:
        src_file = self._find_file(type_name)
        if src_file is None:
            _LOGGER.debug("PayloadResolver: class file not found for %s", type_name)
            return []
        try:
            src = src_file.read_text(errors="replace")
        except OSError:
            return []

        fields: list[FieldDef] = []
        seen: set[str] = set()

        for pat in (_SERIALIZED_NAME_RE, _JSON_NAME_RE):
            for m in pat.finditer(src):
                wire_name = m.group(1)
                java_type = m.group(2).strip()
                java_field = m.group(3)
                if wire_name in seen:
                    continue
                seen.add(wire_name)

                nullable = bool(_NULLABLE_RE.search(src[max(0, m.start() - 50): m.start()]))
                kind = _kind(java_type)
                fields.append(FieldDef(
                    name=java_field,
                    serialized_name=wire_name,
                    kind=kind,
                    required=not nullable,
                    nullable=nullable,
                ))

        if fields:
            _LOGGER.info(
                "PayloadResolver: %s → %d fields (%s)",
                type_name, len(fields), [f.serialized_name for f in fields],
            )
        return fields

    def _find_file(self, type_name: str) -> Path | None:
        # Direct match: TypeName.java anywhere in sources
        candidates = list(self._sources.rglob(f"{type_name}.java"))
        if candidates:
            return candidates[0]
        return None


# ── helpers ───────────────────────────────────────────────────────────────────


def _kind(java_type: str) -> FieldKind:
    """Map a Java type string to FieldKind."""
    t = java_type.lower().strip()
    if _COLLECTION_RE.match(java_type) or t.endswith("[]"):
        return FieldKind.ARRAY
    if t in ("string", "charsequence"):
        return FieldKind.STRING
    if t in ("int", "integer", "long", "short", "byte"):
        return FieldKind.INTEGER
    if t in ("float", "double"):
        return FieldKind.NUMBER
    if t in ("boolean", "bool"):
        return FieldKind.BOOLEAN
    # Anything else (nested object, enum, etc.)
    return FieldKind.OBJECT
