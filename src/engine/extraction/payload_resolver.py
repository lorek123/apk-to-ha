# SPDX-License-Identifier: MIT
"""P2-2 — Payload class resolver.

For each Java class name (typically the @Body or return type of a Retrofit method),
find its definition in the decompiled source tree and extract typed field descriptors
from @SerializedName (Gson) and @Json(name=...) (Moshi) annotations.

Handles:
  - @SerializedName("wire_name") → FieldDef with serialized_name set
  - @Json(name = "wire_name")    → same
  - Constant references (@SerializedName(Api.MUTE)) resolved via the app's
    static final String constants
  - Primitive Java types → FieldKind mapping
  - Collections (List<T>, ArrayList<T>) → FieldKind.ARRAY
  - Nested classes (resolved shallowly — 1 level deep)
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from pathlib import Path

from ..ir.models import FieldDef, FieldKind, PayloadSchema

_LOGGER = logging.getLogger(__name__)

# ── patterns ──────────────────────────────────────────────────────────────────

# Annotation argument: a string literal ("wire") or a constant reference
# (RobotApi.MUTE / MUTE), optionally as value=/name=. Group "lit" or "const".
_NAME_ARG = r'(?:"(?P<lit>[^"]+)"|(?P<const>[A-Za-z_][\w.]*))'
# After the annotation: other annotations, modifiers, then "<type> <field>;"
_FIELD_TAIL = (
    r"(?:\s*@[\w.]+(?:\([^)]*\))?\s*)*"  # other annotations
    r"\s*(?:public|private|protected)?\s*"
    r"(?:static\s+)?(?:final\s+)?(?:transient\s+)?(?:volatile\s+)?"
    r"(?P<type>[\w.<>, ]+?)\s+(?P<field>\w+)\s*[;=]"
)

# @SerializedName("wire") / @SerializedName(Api.WIRE) / @SerializedName(value = "wire", ...)
_SERIALIZED_NAME_RE = re.compile(
    r"@SerializedName\s*\(\s*(?:value\s*=\s*)?" + _NAME_ARG + r"\s*(?:,[^)]*)?\)" + _FIELD_TAIL,
    re.DOTALL,
)

# @Json(name = "wire") — Moshi
_JSON_NAME_RE = re.compile(
    r"@Json\s*\(\s*name\s*=\s*" + _NAME_ARG + r"\s*\)" + _FIELD_TAIL,
    re.DOTALL,
)

_EXTENDS_RE = re.compile(r"\bclass\s+\w+(?:<[^>]*>)?\s+extends\s+(\w+)")
_MAX_INHERITANCE_DEPTH = 3

# Collection wrappers that indicate ARRAY kind
_COLLECTION_RE = re.compile(r"\b(?:List|ArrayList|LinkedList|Set|Collection|Array)\s*<")

# Nullable markers
_NULLABLE_RE = re.compile(r"@(?:Nullable|Null)\b")


# ── resolver ──────────────────────────────────────────────────────────────────


def serialized_fields(
    src: str, constants: Mapping[str, str] | None = None
) -> list[tuple[str, str, str, int]]:
    """(wire_name, java_type, java_field, offset) for each Gson/Moshi-annotated field.

    Constant references are resolved through *constants* (simple name → string
    value, e.g. {"MUTE": "mute"}); unresolvable ones are skipped, never guessed.
    """
    out: list[tuple[str, str, str, int]] = []
    for pat in (_SERIALIZED_NAME_RE, _JSON_NAME_RE):
        for m in pat.finditer(src):
            wire = m.group("lit")
            if wire is None:
                const = m.group("const")
                wire = (constants or {}).get(const.rsplit(".", 1)[-1])
                if wire is None:
                    _LOGGER.debug("unresolved serialized-name constant %s", const)
                    continue
            out.append((wire, m.group("type").strip(), m.group("field"), m.start()))
    return out


def top_level_body(src: str, class_name: str) -> str:
    """Text directly inside *class_name*'s braces (depth 1), without nested blocks.

    Falls back to the whole source if the class declaration isn't found.
    """
    m = re.search(rf"\bclass\s+{re.escape(class_name)}\b[^{{]*\{{", src)
    if m is None:
        return src
    out: list[str] = []
    depth = 1
    for ch in src[m.end() :]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        elif depth == 1:
            out.append(ch)
    return "".join(out)


class PayloadResolver:
    """Resolves a Java type name to its wire-name FieldDef list."""

    def __init__(self, apk_out_dir: Path, constants: Mapping[str, str] | None = None) -> None:
        self._sources = apk_out_dir / "sources"
        self._constants = constants or {}
        self._cache: dict[str, list[FieldDef]] = {}

    def resolve(self, type_name: str) -> PayloadSchema:
        """Return a PayloadSchema for *type_name*; fields=[] if class not found."""
        is_collection = False
        # Unwrap List<T> / ArrayList<T>
        col_m = re.match(r"(?:List|ArrayList|LinkedList|Set|Collection)<(\w+)>", type_name)
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

    def _extract_fields(self, type_name: str, depth: int = 0) -> list[FieldDef]:
        src_file = self._find_file(type_name)
        if src_file is None:
            _LOGGER.debug("PayloadResolver: class file not found for %s", type_name)
            return []
        try:
            src = src_file.read_text(errors="replace")
        except OSError:
            return []

        # Only the class's own fields: nested classes (e.g. a list item type) and
        # method bodies are other scopes and must not flatten into this payload.
        body = top_level_body(src, type_name)
        fields: list[FieldDef] = []
        seen: set[str] = set()

        for wire_name, java_type, java_field, offset in serialized_fields(body, self._constants):
            if wire_name in seen:
                continue
            seen.add(wire_name)

            nullable = bool(_NULLABLE_RE.search(body[max(0, offset - 50) : offset]))
            fields.append(
                FieldDef(
                    name=java_field,
                    serialized_name=wire_name,
                    kind=_kind(java_type),
                    required=not nullable,
                    nullable=nullable,
                )
            )

        parent = _EXTENDS_RE.search(src[: src.find("{")] if "{" in src else src)
        if parent and depth < _MAX_INHERITANCE_DEPTH:
            for f in self._extract_fields(parent.group(1), depth + 1):
                if f.serialized_name not in seen:
                    seen.add(f.serialized_name or f.name)
                    fields.append(f)

        if fields:
            _LOGGER.info(
                "PayloadResolver: %s → %d fields (%s)",
                type_name,
                len(fields),
                [f.serialized_name for f in fields],
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
