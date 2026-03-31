"""Scope-aware call resolver — resolves funcref: nodes to real func: definitions."""

from __future__ import annotations

import logging
from collections import defaultdict

from archgraph.graph.schema import Edge, GraphData, Node, NodeLabel, EdgeType

logger = logging.getLogger(__name__)


class CallResolver:
    """Resolves unresolved funcref: call targets to actual function definitions.

    Uses a 4-level fallback chain:
      1. Qualifier match (e.g., funcref:Counter.increment -> Counter class method)
      2. Intra-file match (caller and callee in same file)
      3. Import match (follow import edges to find the source)
      4. Global unique (only one definition with that name exists)
    """

    def __init__(self, graph: GraphData) -> None:
        self._graph = graph
        self._build_indexes()

    def _build_indexes(self) -> None:
        """Build symbol table, import map, and file set from graph data."""
        self._file_funcs: dict[str, list[Node]] = defaultdict(list)
        self._name_to_defs: dict[str, list[Node]] = defaultdict(list)
        self._qualified_to_def: dict[str, Node] = {}
        self._import_map: dict[tuple[str, str], str] = {}
        self._file_set: set[str] = set()

        node_map: dict[str, Node] = {}
        for node in self._graph.nodes:
            node_map[node.id] = node

        for node in self._graph.nodes:
            if node.label == NodeLabel.FUNCTION and not node.id.startswith("funcref:"):
                name = node.properties.get("name", "")
                file_path = node.properties.get("file", "")
                if name:
                    self._name_to_defs[name].append(node)
                if file_path:
                    self._file_funcs[file_path].append(node)

            elif node.label == NodeLabel.FILE:
                path = node.properties.get("path", "")
                if path:
                    self._file_set.add(path)

        # Build qualified index from CONTAINS edges (Class -> Function)
        for edge in self._graph.edges:
            if edge.type == EdgeType.CONTAINS:
                source = node_map.get(edge.source_id)
                target = node_map.get(edge.target_id)
                if (
                    source
                    and target
                    and source.label == NodeLabel.CLASS
                    and target.label == NodeLabel.FUNCTION
                    and not target.id.startswith("funcref:")
                ):
                    class_name = source.properties.get("name", "")
                    func_name = target.properties.get("name", "")
                    if class_name and func_name:
                        self._qualified_to_def[f"{class_name}.{func_name}"] = target

        # Build import map from IMPORTS edges with names property
        for edge in self._graph.edges:
            if edge.type == EdgeType.IMPORTS:
                source_node = node_map.get(edge.source_id)
                if not source_node or source_node.label != NodeLabel.FILE:
                    continue
                source_file = source_node.properties.get("path", "")
                names_str = edge.properties.get("names", "")
                target_node = node_map.get(edge.target_id)
                module_spec = target_node.properties.get("name", "") if target_node else ""
                if source_file and module_spec and names_str:
                    for name in names_str.split(","):
                        name = name.strip()
                        if name:
                            self._import_map[(source_file, name)] = module_spec

    # ── Resolution ────────────────────────────────────────────────────────

    def resolve(self) -> GraphData:
        """Resolve funcref: nodes to real func: definitions.

        Iterates all CALLS edges targeting funcref: nodes. For each,
        applies the 4-level resolution chain per-caller. After all edges
        are processed, removes orphaned funcref: nodes.
        """
        node_map: dict[str, Node] = {n.id: n for n in self._graph.nodes}
        total_calls = 0
        resolved_count = 0

        for edge in self._graph.edges:
            if edge.type != EdgeType.CALLS:
                continue
            if not edge.target_id.startswith("funcref:"):
                continue

            total_calls += 1
            caller = node_map.get(edge.source_id)
            if not caller:
                continue
            caller_file = caller.properties.get("file", "")
            caller_line = caller.properties.get("line_start", 0)

            funcref_node = node_map.get(edge.target_id)
            callee_name = funcref_node.properties.get("name", "") if funcref_node else ""
            qualifier = edge.properties.get("qualifier")

            target = self._resolve_single(callee_name, qualifier, caller_file, caller_line)
            if target:
                edge.target_id = target.id
                edge.properties["resolved"] = True
                resolved_count += 1

        # Remove orphaned funcref: nodes (no remaining edges point to them)
        referenced_targets = {e.target_id for e in self._graph.edges}
        referenced_sources = {e.source_id for e in self._graph.edges}
        referenced_ids = referenced_targets | referenced_sources
        self._graph.nodes = [
            n for n in self._graph.nodes
            if not n.id.startswith("funcref:") or n.id in referenced_ids
        ]

        if total_calls > 0:
            pct = (resolved_count / total_calls) * 100
            logger.info(
                "Resolved %d/%d calls (%.1f%%), %d unresolved (external/ambiguous)",
                resolved_count, total_calls, pct, total_calls - resolved_count,
            )
        else:
            logger.info("No funcref: calls to resolve")

        return self._graph

    def _resolve_single(
        self,
        callee_name: str,
        qualifier: str | None,
        caller_file: str,
        caller_line: int = 0,
    ) -> Node | None:
        """Try to resolve a single call through the 4-level chain."""
        if not callee_name:
            return None

        # Step 1: Qualifier match
        if qualifier:
            qualified_key = f"{qualifier}.{callee_name}"
            if qualified_key in self._qualified_to_def:
                return self._qualified_to_def[qualified_key]

        # Step 2: Intra-file match
        if caller_file:
            file_funcs = self._file_funcs.get(caller_file, [])
            matches = [f for f in file_funcs if f.properties.get("name") == callee_name]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return self._pick_closest(matches, caller_line)

        # Step 3: Import match
        if caller_file:
            module_spec = self._import_map.get((caller_file, callee_name))
            if module_spec:
                resolved_file = self._resolve_module_path(caller_file, module_spec)
                if resolved_file:
                    file_funcs = self._file_funcs.get(resolved_file, [])
                    matches = [
                        f for f in file_funcs if f.properties.get("name") == callee_name
                    ]
                    if matches:
                        return matches[0]

        # Step 4: Global unique
        defs = self._name_to_defs.get(callee_name, [])
        if len(defs) == 1:
            return defs[0]

        return None

    def _pick_closest(self, candidates: list[Node], caller_line: int) -> Node:
        """Pick the candidate nearest to the caller by line number."""
        return min(
            candidates,
            key=lambda n: abs(n.properties.get("line_start", 0) - caller_line),
        )

    # ── Module path resolution ────────────────────────────────────────────

    def _resolve_module_path(
        self, caller_file: str, module_specifier: str,
    ) -> str | None:
        """Resolve a module specifier to a file path in _file_set.

        Returns the matching file path, or None if not found (external/stdlib).
        """
        # Normalize backslashes to forward slashes for consistent matching
        normalized_files = {p.replace("\\", "/"): p for p in self._file_set}
        caller_norm = caller_file.replace("\\", "/")

        # Relative JS/TS imports: ./foo, ../foo
        if module_specifier.startswith("."):
            from posixpath import dirname, normpath, join
            caller_dir = dirname(caller_norm)
            base = normpath(join(caller_dir, module_specifier))
            for ext in (
                ".ts", ".tsx", ".js", ".jsx",
                "/index.ts", "/index.tsx", "/index.js", "/index.jsx",
            ):
                candidate = base + ext
                if candidate in normalized_files:
                    return normalized_files[candidate]
            return None

        # Rust crate imports: crate::foo::bar -> src/foo/bar.rs or src/foo/bar/mod.rs
        if module_specifier.startswith("crate::"):
            path_part = module_specifier[7:].replace("::", "/")
            for candidate in (f"src/{path_part}.rs", f"src/{path_part}/mod.rs"):
                if candidate in normalized_files:
                    return normalized_files[candidate]
            return None

        # Java/Kotlin package imports: com.example.Foo -> com/example/Foo.java or .kt
        if "." in module_specifier and not module_specifier.startswith("."):
            path_part = module_specifier.replace(".", "/")
            for ext in (".java", ".kt"):
                candidate = path_part + ext
                if candidate in normalized_files:
                    return normalized_files[candidate]
            for ext in (".java", ".kt"):
                for prefix in ("src/main/java/", "src/main/kotlin/", "src/"):
                    candidate = prefix + path_part + ext
                    if candidate in normalized_files:
                        return normalized_files[candidate]
            return None

        # Go imports: "pkg/path" -> look for files in the last segment dir
        if "/" in module_specifier:
            last_segment = module_specifier.rsplit("/", 1)[-1]
            for norm_path in normalized_files:
                parts = norm_path.split("/")
                if len(parts) >= 2 and parts[-2] == last_segment:
                    return normalized_files[norm_path]
            return None

        # Simple name — try as-is with common extensions
        for ext in (
            ".ts", ".tsx", ".js", ".jsx", ".rs", ".go",
            ".java", ".kt", ".c", ".cpp", ".h",
        ):
            if module_specifier + ext in normalized_files:
                return normalized_files[module_specifier + ext]

        return None
