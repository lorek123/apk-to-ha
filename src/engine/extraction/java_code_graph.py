# SPDX-License-Identifier: MIT
"""P2-5 helper — call graph built from decompiled .java files via tree-sitter.

Replaces the depth-2 same-file text search in signing_tracer with proper BFS
over a pre-built call graph, enabling cross-file method resolution.

Graph keys use `ClassName.methodName`.  When a caller records an invocation by
short name only (e.g. `buildMsg`), BFS resolves it by matching `*.buildMsg`.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from pathlib import Path

try:
    import tree_sitter_java as _tsjava
    from tree_sitter import Language, Node, Parser

    _JAVA_LANG = Language(_tsjava.language())
    _PARSER = Parser(_JAVA_LANG)
    _TREE_SITTER_AVAILABLE = True
except Exception:  # pragma: no cover
    _TREE_SITTER_AVAILABLE = False

_LOGGER = logging.getLogger(__name__)


class JavaCodeGraph:
    """Lightweight call graph derived from tree-sitter Java AST.

    Attributes
    ----------
    method_sources : dict[str, str]
        Qualified method key → source text of the method body (the block {…}).
    method_callees : dict[str, list[str]]
        Qualified method key → list of short callee names found in body.
    method_callers : dict[str, list[str]]
        Short callee name → list of qualified method keys that call it.
    """

    def __init__(self) -> None:
        self.method_sources: dict[str, str] = {}
        self.method_callees: dict[str, list[str]] = defaultdict(list)
        self.method_callers: dict[str, list[str]] = defaultdict(list)
        self._source_bytes: dict[str, bytes] = {}

    # ── public factory ────────────────────────────────────────────────────────

    @classmethod
    def build(cls, sources_dir: Path) -> JavaCodeGraph:
        """Parse all .java files under *sources_dir* and return a populated graph."""
        graph = cls()
        if not _TREE_SITTER_AVAILABLE:
            _LOGGER.warning("java_code_graph: tree-sitter unavailable — graph empty")
            return graph

        java_files = list(sources_dir.rglob("*.java"))
        _LOGGER.debug("java_code_graph: scanning %d .java files", len(java_files))
        for jf in java_files:
            try:
                graph._index_file(jf)
            except Exception as exc:
                _LOGGER.debug("java_code_graph: error indexing %s: %s", jf, exc)

        _LOGGER.debug("java_code_graph: indexed %d methods", len(graph.method_sources))
        return graph

    # ── public queries ────────────────────────────────────────────────────────

    def get_method_source(self, key: str) -> str | None:
        """Return source text for *key* (exact) or for `*.key` (short name match)."""
        if key in self.method_sources:
            return self.method_sources[key]
        # Short-name lookup: return the first match
        suffix = "." + key
        for k, src in self.method_sources.items():
            if k.endswith(suffix):
                return src
        return None

    def bfs_from(self, start: str, max_hops: int = 4) -> list[str]:
        """Return all method keys reachable from *start* within *max_hops* hops.

        *start* may be a qualified key or a short name.
        """
        resolved = self._resolve_key(start)
        if not resolved:
            return []

        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque((k, 0) for k in resolved)
        result: list[str] = []

        while queue:
            key, hops = queue.popleft()
            if key in visited or hops > max_hops:
                continue
            visited.add(key)
            result.append(key)
            for callee in self.method_callees.get(key, []):
                for resolved_callee in self._resolve_key(callee):
                    if resolved_callee not in visited:
                        queue.append((resolved_callee, hops + 1))

        return result

    def callers_of(self, method_name: str) -> list[str]:
        """Return qualified callers of any method whose short name matches."""
        return list(self.method_callers.get(method_name, []))

    def subgraph_text(self, start: str, max_hops: int = 3) -> str:
        """Return concatenated source text of all reachable methods.

        Useful for feeding a focused context window to the LLM escalation path.
        """
        keys = self.bfs_from(start, max_hops)
        parts: list[str] = []
        for k in keys:
            src = self.method_sources.get(k)
            if src:
                parts.append(f"// --- {k} ---\n{src}")
        return "\n\n".join(parts)

    # ── private: file indexing ────────────────────────────────────────────────

    def _index_file(self, path: Path) -> None:
        raw = path.read_bytes()
        tree = _PARSER.parse(raw)
        src_text = raw.decode(errors="replace")

        class_name = _extract_class_name(tree.root_node, src_text)
        if class_name is None:
            class_name = path.stem

        for method_node in _find_nodes(tree.root_node, "method_declaration"):
            name_node = method_node.child_by_field_name("name")
            body_node = method_node.child_by_field_name("body")
            if name_node is None or body_node is None:
                continue

            method_name = _node_text(name_node, src_text)
            key = f"{class_name}.{method_name}"

            # Body text: the block including braces
            body_src = src_text[body_node.start_byte : body_node.end_byte]
            self.method_sources[key] = body_src
            self._source_bytes[key] = raw

            # Collect callees from inside this body
            for inv_node in _find_nodes(body_node, "method_invocation"):
                callee_name_node = inv_node.child_by_field_name("name")
                if callee_name_node is None:
                    continue
                callee = _node_text(callee_name_node, src_text)
                if callee not in self.method_callees[key]:
                    self.method_callees[key].append(callee)
                if key not in self.method_callers[callee]:
                    self.method_callers[callee].append(key)

    def _resolve_key(self, name: str) -> list[str]:
        """Resolve a name to qualified keys: exact first, then suffix match."""
        if name in self.method_sources:
            return [name]
        suffix = "." + name
        return [k for k in self.method_sources if k.endswith(suffix)]


# ── tree-sitter helpers ───────────────────────────────────────────────────────


def _find_nodes(node: Node, node_type: str) -> list[Node]:
    """Recursively collect all descendant nodes of *node_type*."""
    results: list[Node] = []
    if node.type == node_type:
        results.append(node)
    for child in node.children:
        results.extend(_find_nodes(child, node_type))
    return results


def _node_text(node: Node, src: str) -> str:
    return src[node.start_byte : node.end_byte]


def _extract_class_name(root: Node, src: str) -> str | None:
    """Return the simple class name from the first class_declaration in *root*."""
    for node in root.children:
        if node.type == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                return _node_text(name_node, src)
    return None
