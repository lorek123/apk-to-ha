# SPDX-License-Identifier: MIT
"""P1-1 — Typed async client for the JADX-AI-MCP plugin HTTP API.

The jadx-ai-mcp plugin runs inside JADX-GUI and serves a REST API on
localhost:8650. This client wraps every endpoint with typed return values
and returns safe defaults (empty list / None) when the plugin is not reachable,
so all callers can use it without null-checks beyond "if result:".

Usage:
    async with JadxClient() as jadx:
        if await jadx.is_available():
            src = await jadx.get_class_source("com.example.Foo")

The pipeline falls back to file-based scanning when is_available() returns False.
"""
from __future__ import annotations

import logging
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8650
_DEFAULT_TIMEOUT = 30.0


class JadxClient:
    """Async REST client for the jadx-ai-mcp JADX-GUI plugin (port 8650 by default)."""

    def __init__(
        self,
        host: str = _DEFAULT_HOST,
        port: int = _DEFAULT_PORT,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._base = f"http://{host}:{port}"
        self._timeout = timeout
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> "JadxClient":
        self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    # ── internal helpers ───────────────────────────────────────────────────────

    async def _get(
        self, endpoint: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """GET endpoint; returns {} on any network or HTTP error."""
        assert self._session is not None, "JadxClient must be used as an async context manager"
        url = f"{self._base}/{endpoint.lstrip('/')}"
        try:
            async with self._session.get(
                url,
                params=params or {},
                timeout=aiohttp.ClientTimeout(total=self._timeout),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)
                return dict(data) if isinstance(data, dict) else {}
        except Exception as exc:
            _LOGGER.debug("JADX plugin unavailable (%s): %s", endpoint, exc)
            return {}

    # ── lifecycle / health ─────────────────────────────────────────────────────

    async def is_available(self) -> bool:
        """Return True if the JADX plugin HTTP server responds to /health."""
        result = await self._get("health")
        return bool(result) and "error" not in result

    # ── class queries ──────────────────────────────────────────────────────────

    async def get_all_classes(self, offset: int = 0, count: int = 0) -> list[str]:
        """Return all class names in the loaded APK (paginated)."""
        data = await self._get("all-classes", {"offset": offset, "count": count})
        return [str(c) for c in data.get("classes", [])]

    async def get_class_source(self, class_name: str) -> str | None:
        """Return the decompiled Java source for *class_name*, or None."""
        data = await self._get("class-source", {"class_name": class_name})
        src = data.get("source") or data.get("code")
        return str(src) if src else None

    async def get_methods_of_class(self, class_name: str) -> list[str]:
        """Return all method signatures in *class_name*."""
        data = await self._get("methods-of-class", {"class_name": class_name})
        return [str(m) for m in data.get("methods", [])]

    async def get_fields_of_class(self, class_name: str) -> list[dict[str, Any]]:
        """Return all field descriptors for *class_name*."""
        data = await self._get("fields-of-class", {"class_name": class_name})
        return [dict(f) for f in data.get("fields", [])]

    async def get_method_by_name(
        self, class_name: str, method_name: str
    ) -> dict[str, Any] | None:
        """Return the method descriptor dict, or None if not found."""
        data = await self._get(
            "method-by-name", {"class_name": class_name, "method_name": method_name}
        )
        return data if data and "error" not in data else None

    async def get_main_activity(self) -> dict[str, Any] | None:
        """Return the main activity class info dict, or None."""
        data = await self._get("main-activity")
        return data if data and "error" not in data else None

    async def get_main_application_class_names(self) -> list[str]:
        """Return names of top-level application classes."""
        data = await self._get("main-application-classes-names")
        return [str(c) for c in data.get("classes", [])]

    # ── search ─────────────────────────────────────────────────────────────────

    async def search_classes_by_keyword(
        self,
        search_term: str,
        package: str = "",
        search_in: str = "code",
        offset: int = 0,
        count: int = 20,
    ) -> list[str]:
        """Search classes by keyword; returns matching class names."""
        data = await self._get(
            "search-classes-by-keyword",
            {
                "search_term": search_term,
                "package": package,
                "search_in": search_in,
                "offset": offset,
                "count": count,
            },
        )
        raw = data.get("classes") or data.get("results") or []
        return [str(c) for c in raw]

    async def search_method_by_name(self, method_name: str) -> list[dict[str, Any]]:
        """Search for methods with *method_name* across all classes."""
        data = await self._get("search-method", {"method_name": method_name})
        raw = data.get("methods") or data.get("results") or []
        return [dict(m) for m in raw]

    # ── resources ──────────────────────────────────────────────────────────────

    async def get_android_manifest(self) -> str | None:
        """Return raw AndroidManifest.xml content, or None."""
        data = await self._get("manifest")
        content = data.get("content") or data.get("manifest")
        return str(content) if content else None

    async def get_strings(self, offset: int = 0, count: int = 0) -> list[dict[str, Any]]:
        """Return string resources from all strings.xml files."""
        data = await self._get("strings", {"offset": offset, "count": count})
        return [dict(s) for s in data.get("strings", [])]

    async def get_all_resource_file_names(self) -> list[str]:
        """Return names of all resource files in the APK."""
        data = await self._get("list-all-resource-files-names")
        return [str(f) for f in data.get("files", [])]

    async def get_resource_file(self, file_name: str) -> str | None:
        """Return the content of a resource file by name, or None."""
        data = await self._get("get-resource-file", {"file_name": file_name})
        content = data.get("content")
        return str(content) if content else None

    # ── cross-references ───────────────────────────────────────────────────────

    async def get_xrefs_to_class(
        self, class_name: str, offset: int = 0, count: int = 20
    ) -> list[dict[str, Any]]:
        """Return locations that reference *class_name*."""
        data = await self._get(
            "xrefs-to-class",
            {"class_name": class_name, "offset": offset, "count": count},
        )
        return [dict(r) for r in data.get("references", [])]

    async def get_xrefs_to_method(
        self, class_name: str, method_name: str, offset: int = 0, count: int = 20
    ) -> list[dict[str, Any]]:
        """Return call sites for *class_name*.*method_name*."""
        data = await self._get(
            "xrefs-to-method",
            {
                "class_name": class_name,
                "method_name": method_name,
                "offset": offset,
                "count": count,
            },
        )
        return [dict(r) for r in data.get("references", [])]

    async def get_xrefs_to_field(
        self, class_name: str, field_name: str, offset: int = 0, count: int = 20
    ) -> list[dict[str, Any]]:
        """Return access sites for *class_name*.*field_name*."""
        data = await self._get(
            "xrefs-to-field",
            {
                "class_name": class_name,
                "field_name": field_name,
                "offset": offset,
                "count": count,
            },
        )
        return [dict(r) for r in data.get("references", [])]

    async def get_smali(self, class_name: str) -> str | None:
        """Return Smali bytecode for *class_name*, or None."""
        data = await self._get("smali-of-class", {"class_name": class_name})
        content = data.get("smali") or data.get("content")
        return str(content) if content else None
