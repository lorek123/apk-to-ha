# SPDX-License-Identifier: MIT
"""P2-1e — Ktor client requests (Kotlin / Kotlin Multiplatform apps).

Ktor's request builders are inline functions, so decompiled code shows the
expanded builder rather than a call:

    HttpRequestBuilder b = new HttpRequestBuilder();
    HttpRequestKt.url(b, str3);                     // str3 = base + "/api/status"
    UtilsKt.parameter(b, "path", value);            // query parameter
    b.setMethod(HttpMethod.INSTANCE.getGet());      // method
    … Reflection.getOrCreateKotlinClass(DeviceStatusNetwork.class) …   // body<T>()

and form posts as ``FormBuildersKt.submitForm(client, base + "/delete", parameters)``
with fields from ``parameters.append("path", …)``. Response classes (kotlinx
serialization, property names = JSON keys) give typed response fields.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..ir.models import Direction, Endpoint, FieldDef, FieldKind, TransportType
from . import confidence
from .app_sources import app_source_files
from .volley_scanner import _resolve_locals, url_template

_LOGGER = logging.getLogger(__name__)

_BUILDER_URL = re.compile(r"HttpRequestKt\.url\(\s*(\w+)\s*,\s*([^;]+?)\)\s*;")
_SUBMIT_FORM = re.compile(r"FormBuildersKt\.submitForm(?:\$default)?\(\s*[\w.]+\s*,\s*([^,]+?)\s*,")
_FORM_FIELD = re.compile(r'\.append\(\s*"(\w+)"')
_RESPONSE_CLASS = re.compile(
    r"Reflection\.(?:getOrCreateKotlinClass|typeOf|nullableTypeOf)\((\w+)\.class\)"
)
_CLASS_FIELD = re.compile(r"^\s+private final ([\w.<>]+) (\w+);", re.MULTILINE)
_WINDOW = 2500
_KINDS = {
    "int": FieldKind.INTEGER, "Integer": FieldKind.INTEGER,
    "long": FieldKind.INTEGER, "Long": FieldKind.INTEGER,
    "double": FieldKind.NUMBER, "Double": FieldKind.NUMBER,
    "float": FieldKind.NUMBER, "Float": FieldKind.NUMBER,
    "boolean": FieldKind.BOOLEAN, "Boolean": FieldKind.BOOLEAN,
    "String": FieldKind.STRING,
}  # fmt: skip


def scan(apk_out_dir: Path, app_package: str) -> list[Endpoint]:
    sources = apk_out_dir / "sources"
    if not sources.exists():
        return []
    all_texts = {f: f.read_text(errors="replace") for f in app_source_files(sources, app_package)}
    classes = {f.stem: t for f, t in all_texts.items()}
    texts = {f: t for f, t in all_texts.items() if "HttpRequestBuilder" in t or "submitForm" in t}

    endpoints: dict[str, Endpoint] = {}
    for path, src in texts.items():
        cls = path.stem.split("$")[0]
        for m in _BUILDER_URL.finditer(src):
            builder, url_expr = m.group(1), m.group(2)
            template = url_template(_resolve_locals(src, m.start(), url_expr))
            if template is None:
                continue
            window = _builder_span(src, m.start(), m.end())
            b = re.escape(builder)
            verb = re.search(rf"\b{b}\.setMethod\(HttpMethod\.\w+\.get(\w+)\(\)\)", window)
            fields = [
                FieldDef(name=k, serialized_name=k, kind=FieldKind.STRING, location="query")
                for k in re.findall(rf'UtilsKt\.parameter\(\s*{b}\s*,\s*"(\w+)"', window)
            ]
            if re.search(rf"\b{b}\.setBody\(", window):
                # A body we can't see into: never send it empty from a parameterless button.
                fields.append(
                    FieldDef(name="body", kind=FieldKind.OBJECT, required=True, location="body")
                )
            response = _RESPONSE_CLASS.search(window)
            _add(
                endpoints,
                f"{verb.group(1).upper() if verb else 'GET'} {template}",
                cls,
                fields,
                _response_fields(classes.get(response.group(1))) if response else [],
            )
        for m in _SUBMIT_FORM.finditer(src):
            template = url_template(_resolve_locals(src, m.start(), m.group(1)))
            if template is None:
                continue
            fields = [
                FieldDef(name=k, serialized_name=k, kind=FieldKind.STRING, location="form")
                for k in dict.fromkeys(_FORM_FIELD.findall(_form_builder(src, m.start())))
            ]
            _add(endpoints, f"POST {template}", cls, fields, [])

    result = list(endpoints.values())
    if result:
        _LOGGER.info("ktor_scanner: %d endpoints", len(result))
    return result


def _form_builder(src: str, call_start: int) -> str:
    """Code that fills a submitForm's parameters.

    ``parameters { append(…) }`` compiles to a synthetic ``deleteItem$lambda$0(…,
    ParametersBuilder)`` referenced just before the call; otherwise the appends are
    inline, between the previous request and this one.
    """
    before = src[max(0, call_start - _WINDOW) : call_start]
    prev = max(before.rfind("submitForm"), before.rfind("new HttpRequestBuilder"))
    before = before[prev + 1 :] if prev != -1 else before
    lambdas = re.findall(r"\.(\w+\$lambda\$\d+)\(", before)
    if lambdas:
        decl = re.search(rf"\b{re.escape(lambdas[-1])}\([^)]*ParametersBuilder[^)]*\)\s*\{{", src)
        if decl:
            end = src.find("\n    }", decl.end())
            return src[decl.end() : end if end != -1 else decl.end() + _WINDOW]
    return before


def _builder_span(src: str, url_start: int, url_end: int) -> str:
    """This request's builder code: from its `new HttpRequestBuilder()` to the next one.

    The method may be set before or after url(), so look both ways, but never
    into a neighbouring request (the builder variable name is often reused).
    """
    start = src.rfind("new HttpRequestBuilder", 0, url_start)
    start = max(start, url_start - _WINDOW) if start != -1 else url_start
    nxt = src.find("new HttpRequestBuilder", url_end)
    end = min(nxt if nxt != -1 else len(src), url_end + _WINDOW)
    return src[start:end]


def _add(
    endpoints: dict[str, Endpoint],
    cmd: str,
    cls: str,
    fields: list[FieldDef],
    response: list[FieldDef],
) -> None:
    existing = endpoints.get(cmd)
    if existing and len(existing.request_fields) + len(existing.response_fields) >= len(
        fields
    ) + len(response):
        return  # Kotlin coroutines duplicate each request across resume paths
    endpoints[cmd] = Endpoint(
        cmd=cmd,
        transport=TransportType.HTTP_REST,
        direction=Direction.TO_DEVICE,
        awaits_response=True,
        request_fields=fields,
        response_fields=response,
        source_class=cls,
        confidence=confidence.score(
            confidence.NAME_REQUEST_CALL,
            confidence.FIELDS_TYPED if fields else confidence.FIELDS_NONE,
        ),
    )


def _response_fields(src: str | None) -> list[FieldDef]:
    """Scalar properties of a kotlinx-serializable class (property names are JSON keys)."""
    if src is None:
        return []
    first_class_end = src.find("\n}")
    fields = []
    for java_type, name in dict.fromkeys(_CLASS_FIELD.findall(src[:first_class_end])):
        kind = _KINDS.get(java_type)
        if kind is not None:
            nullable = java_type[:1].isupper() and java_type != "String"
            fields.append(FieldDef(name=name, serialized_name=name, kind=kind, nullable=nullable))
    return fields
