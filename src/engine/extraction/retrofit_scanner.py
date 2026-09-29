# SPDX-License-Identifier: MIT
"""P2-1 / P2-3 — Retrofit/OkHttp annotation scanner.

Scans decompiled Java source for:
  P2-1: @GET/@POST/@PUT/@DELETE/@PATCH/@HEAD  → HTTP verb + path
        @Headers({...})                       → static header dict
        @Header("name") / @HeaderMap          → dynamic header params
        @Body SomeType                        → request payload class name
        Call<SomeType> / Observable<SomeType> → response payload class name
  P2-3: `implements Interceptor`              → detects OkHttp Interceptor
        `.addHeader(...)` / `.header(...)`    → headers added dynamically
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..ir.models import Direction, Endpoint, FieldDef, FieldKind, TransportType
from . import confidence
from .app_sources import app_source_files

_LOGGER = logging.getLogger(__name__)

# ── compiled patterns ─────────────────────────────────────────────────────────

_VERB_RE = re.compile(
    r'@(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(\s*"([^"]+)"\s*\)',
    re.IGNORECASE,
)
_HEADERS_BLOCK_RE = re.compile(r"@Headers\s*\(\s*\{([^}]+)\}\s*\)", re.DOTALL)
_HEADER_STRING_RE = re.compile(r'"([^"]+?):\s*([^"]+?)"')
_HEADER_PARAM_RE = re.compile(r'@Header\s*\(\s*"([^"]+)"\s*\)')
_HEADERMAP_RE = re.compile(r"@HeaderMap\b")
# @Body matches: "@Body TypeName var" or "@Body @Nullable TypeName var"
_BODY_RE = re.compile(r"@Body\s+(?:@\w+\s+)*(?:[\w.<>, ]*?)(\b[A-Z]\w*)\s+\w+")
# Return types from Retrofit / RxJava wrappers
_RETURN_RE = re.compile(
    r"\b(?:Call|Observable|Single|Maybe|Completable|Flowable|LiveData|Response)"
    r"<(?:Response<)?([A-Z]\w*)>?"
)
_METHOD_NAME_RE = re.compile(r"\b([a-z]\w*)\s*\(", re.MULTILINE)

# P2-3: Interceptor detection
_INTERCEPTOR_IMPL_RE = re.compile(r"\bimplements\b[^{]*\bInterceptor\b")
_INTERCEPTOR_HEADER_RE = re.compile(r'\.(?:addHeader|header)\s*\(\s*"([^"]+)"\s*,')

# ── data model ────────────────────────────────────────────────────────────────


@dataclass
class RetrofitEndpoint:
    """Fully-annotated Retrofit method extracted from one interface file."""

    interface_name: str
    method_name: str
    http_verb: str  # GET / POST / PUT / DELETE / …
    path: str  # raw URL path from annotation
    static_headers: dict[str, str] = field(default_factory=dict)
    dynamic_headers: list[str] = field(default_factory=list)
    has_header_map: bool = False
    body_type: str | None = None  # Java class name for @Body
    response_type: str | None = None  # Generic type from Call<T>
    source_file: str = ""


@dataclass
class InterceptorInfo:
    """P2-3 — One OkHttp Interceptor class that injects headers dynamically."""

    class_name: str
    injected_headers: list[str] = field(default_factory=list)  # header names found


# ── scanner ───────────────────────────────────────────────────────────────────


class RetrofitScanner:
    """Scans the decompiled source tree for Retrofit service interfaces (P2-1)
    and OkHttp Interceptor classes (P2-3).
    """

    def __init__(self, apk_out_dir: Path) -> None:
        self._sources = apk_out_dir / "sources"

    def scan(self, app_package: str) -> tuple[list[RetrofitEndpoint], list[InterceptorInfo]]:
        """Walk source files and return (retrofit_endpoints, interceptors)."""
        java_files = app_source_files(self._sources, app_package)

        endpoints: list[RetrofitEndpoint] = []
        interceptors: list[InterceptorInfo] = []

        for java_file in java_files:
            src = _read(java_file)
            if not src:
                continue
            file_endpoints = _scan_file(src, java_file.stem)
            endpoints.extend(file_endpoints)
            interceptor = _scan_interceptor(src, java_file.stem)
            if interceptor is not None:
                interceptors.append(interceptor)

        if endpoints:
            _LOGGER.info(
                "RetrofitScanner: %d endpoints from %d interceptors",
                len(endpoints),
                len(interceptors),
            )
        return endpoints, interceptors

    def to_ir_endpoints(self, retrofit_eps: list[RetrofitEndpoint]) -> list[Endpoint]:
        """Convert RetrofitEndpoint objects to IR Endpoint objects."""
        result: list[Endpoint] = []
        for ep in retrofit_eps:
            # Infer a minimal field list from what we know statically
            req_fields: list[FieldDef] = []
            if ep.body_type:
                req_fields.append(
                    FieldDef(
                        name="body",
                        serialized_name=None,
                        kind=FieldKind.OBJECT,
                        description=ep.body_type,
                    )
                )
            for hdr in ep.dynamic_headers:
                req_fields.append(
                    FieldDef(
                        name=hdr.lower().replace("-", "_"),
                        serialized_name=hdr,
                        kind=FieldKind.STRING,
                        description=f"@Header {hdr}",
                    )
                )

            resp_fields: list[FieldDef] = []
            if ep.response_type and ep.response_type.lower() not in ("void", "responseBody"):
                resp_fields.append(
                    FieldDef(
                        name="response",
                        serialized_name=None,
                        kind=FieldKind.OBJECT,
                        description=ep.response_type,
                    )
                )

            result.append(
                Endpoint(
                    cmd=f"{ep.http_verb} {ep.path}",
                    transport=TransportType.HTTP_REST,
                    direction=Direction.TO_DEVICE,
                    awaits_response=True,
                    request_fields=req_fields,
                    response_fields=resp_fields,
                    source_class=ep.interface_name,
                    # The method signature declares every parameter.
                    confidence=confidence.score(
                        confidence.NAME_ANNOTATION, confidence.FIELDS_TYPED
                    ),
                )
            )
        return result


# ── file-level helpers ────────────────────────────────────────────────────────


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _extract_static_headers(block: str) -> dict[str, str]:
    """Parse @Headers({"K: V", ...}) in *block* → {K: V}."""
    headers: dict[str, str] = {}
    for hm in _HEADERS_BLOCK_RE.finditer(block):
        inner = hm.group(1)
        for kv in _HEADER_STRING_RE.finditer(inner):
            headers[kv.group(1).strip()] = kv.group(2).strip()
    return headers


def _scan_file(src: str, file_stem: str) -> list[RetrofitEndpoint]:
    """Extract all Retrofit-annotated methods from one source file."""
    endpoints: list[RetrofitEndpoint] = []

    for verb_m in _VERB_RE.finditer(src):
        http_verb = verb_m.group(1).upper()
        path = verb_m.group(2)
        pos = verb_m.start()

        pre = src[max(0, pos - 400) : pos]
        post = src[pos : pos + 800]

        static_headers = _extract_static_headers(pre + post)
        dynamic_headers = _HEADER_PARAM_RE.findall(post)
        has_header_map = bool(_HEADERMAP_RE.search(post))

        body_m = _BODY_RE.search(post)
        body_type = body_m.group(1) if body_m else None

        ret_m = _RETURN_RE.search(post)
        response_type = ret_m.group(1) if ret_m else None

        # Method name: first lowercase-initial identifier followed by '('
        mn_m = _METHOD_NAME_RE.search(post)
        method_name = mn_m.group(1) if mn_m else "unknown"

        endpoints.append(
            RetrofitEndpoint(
                interface_name=file_stem,
                method_name=method_name,
                http_verb=http_verb,
                path=path,
                static_headers=static_headers,
                dynamic_headers=dynamic_headers,
                has_header_map=has_header_map,
                body_type=body_type,
                response_type=response_type,
                source_file=file_stem,
            )
        )

    return endpoints


def _scan_interceptor(src: str, class_name: str) -> InterceptorInfo | None:
    """P2-3: Return InterceptorInfo if this file is an OkHttp Interceptor, else None."""
    if not _INTERCEPTOR_IMPL_RE.search(src):
        return None
    injected = list({m.group(1) for m in _INTERCEPTOR_HEADER_RE.finditer(src)})
    _LOGGER.info("P2-3: OkHttp Interceptor detected in %s, headers=%s", class_name, injected)
    return InterceptorInfo(class_name=class_name, injected_headers=injected)
