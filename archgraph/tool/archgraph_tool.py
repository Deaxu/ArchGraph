"""rlm-agent BaseTool integration — exposes code graph query + management interface."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from archgraph.graph.neo4j_store import Neo4jStore

logger = logging.getLogger(__name__)

# Import BaseTool and tool_method if rlm-agent is installed, otherwise provide stubs.
try:
    from rlm_agent import BaseTool
    from rlm_agent.tools import tool_method
except ImportError:

    class BaseTool:  # type: ignore[no-redef]
        """Stub base class when rlm-agent is not installed."""

    def tool_method(  # type: ignore[no-redef]
        description: str = "", returns: str = ""
    ):  # noqa: ANN201
        """No-op decorator stub."""
        def wrapper(fn):  # noqa: ANN001, ANN202
            return fn
        return wrapper


_DESCRIPTION = """\
Source code knowledge graph stored in Neo4j. Query with Cypher.

## Node Labels & Key Properties

- **File**: path, language, loc, churn_count, last_modified
- **Function**: name, file, line_start, line_end, body, body_lines, body_truncated, \
is_exported, is_input_source, is_dangerous_sink, is_allocator, is_crypto, is_parser, \
is_unsafe, has_unsafe_block, has_transmute, has_force_unwrap, has_goroutine, \
has_channel_op, has_defer
- **Class**: name, file, line_start, line_end, body (shell — method bodies replaced with ...)
- **Struct**: name, file, line_start, body
- **Interface**: name, file, line_start (traits, protocols)
- **Enum**: name, file, line_start
- **Module**: name, path (namespace, package, use/import target)
- **Macro**: name, file, line_start
- **Parameter**: name, type
- **Field**: name, type
- **BasicBlock**: block_index, stmt_count, function, file (CFG node)
- **Commit**: hash, message, date, total_insertions, total_deletions, files_changed
- **Author**: name, email
- **Tag**: name, commit_hash, date (release tags)
- **SecurityFix**: description, commit_hash
- **Dependency**: name, version, manager
- **Vulnerability**: vuln_id, summary, severity, aliases (CVE/GHSA/PYSEC from OSV)
- **Annotation**: type (TODO/HACK/FIXME/UNSAFE/BUG/SECURITY/...), text, line

## Edge Types & Properties

- **CONTAINS**: File → Function/Class/Struct/Enum/Macro
- **CALLS**: Function → Function (resolved=true, source="scip" for compiler-verified; funcref: for unresolved)
- **IMPORTS**: File → Module
- **INHERITS**: Class → Class
- **IMPLEMENTS**: Class → Interface
- **USES_TYPE**: Function → Type
- **OVERRIDES**: Function → Function
- **EXPANDS_MACRO**: Function → Macro
- **DATA_FLOWS_TO**: Function self-edge (from_var, to_var, from_line, to_line)
- **TAINTS**: funcref → funcref (tainted input propagation chain)
- **BRANCHES_TO**: BasicBlock → BasicBlock (CFG edges)
- **MODIFIED_IN**: File → Commit (lines_added, lines_deleted per file per commit)
- **AUTHORED_BY**: Commit → Author
- **TAGGED_AS**: Commit → Tag
- **PARENT**: Commit → Commit
- **DEPENDS_ON**: File → Dependency
- **FIXED_BY**: SecurityFix → Commit
- **AFFECTS**: SecurityFix → File
- **HAS_ANNOTATION**: File → Annotation
- **AFFECTED_BY**: Dependency → Vulnerability

## ID Format

All nodes have a unique `_id` property: `{type}:{path}:{name}:{line}`
Examples: `func:src/main.c:parse_data:42`, `file:inflate.c`, `commit:<hash>`

## Tips

- All nodes also carry the `_Node` label for cross-label queries.
- Use `_id` for exact lookups: `MATCH (n:_Node {_id: $id})`
- `funcref:` prefix = unresolved call target (no definition found in codebase).\
"""


class ArchGraphTool(BaseTool):
    """Source code knowledge graph — Cypher query interface."""

    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "archgraph",
        neo4j_database: str = "neo4j",
    ) -> None:
        self._store = Neo4jStore(
            uri=neo4j_uri,
            user=neo4j_user,
            password=neo4j_password,
            database=neo4j_database,
        )
        self._connected = False

    @property
    def name(self) -> str:
        return "archgraph"

    @property
    def description(self) -> str:
        return _DESCRIPTION

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """Connect to Neo4j."""
        self._store.connect()
        self._connected = True

    def close(self) -> None:
        """Close connection."""
        self._store.close()
        self._connected = False

    def cleanup(self) -> None:
        """Called by rlm-agent when the session closes."""
        self.close()

    def __enter__(self) -> ArchGraphTool:
        self.connect()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _ensure_connected(self) -> None:
        if not self._connected:
            self.connect()

    # ── Tool method ──────────────────────────────────────────────────────────

    @tool_method(
        description="Execute a Cypher query against the code knowledge graph",
        returns="list of result records as dicts",
    )
    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a Cypher query.

        Args:
            cypher: Cypher query string.
            params: Optional query parameters (use $name syntax in Cypher).

        Returns:
            List of result records as dicts.
        """
        self._ensure_connected()
        return self._store.query(cypher, params)


    @tool_method(
        description="Get source code of a symbol by its node ID",
        returns="dict with body, name, file, line range — or error",
    )
    def source(self, symbol_id: str) -> dict[str, Any]:
        """Get source code of a function, class, struct, or other symbol.

        Args:
            symbol_id: Node ID (e.g. "func:src/auth.c:validate:42").

        Returns:
            Dict with body, name, file, line_start, line_end, body_lines.
        """
        self._ensure_connected()
        result = self._store.get_source(symbol_id)
        if result is None:
            return {"error": f"Symbol not found or has no body: {symbol_id}"}
        return result

    @tool_method(
        description=(
            "Extract code graph from a repository. Accepts a git URL or local path. "
            "Auto-detects languages, runs SCIP compiler-backed indexers, and imports into Neo4j."
        ),
        returns="dict with extraction results: nodes, edges, resolved_calls, time",
    )
    def extract(
        self,
        repo: str,
        languages: str = "auto",
        clear_db: bool = True,
    ) -> dict[str, Any]:
        """Extract code graph from a repository.

        Args:
            repo: Git URL (https/ssh) or local directory path.
            languages: Comma-separated languages or 'auto' for detection.
            clear_db: Clear existing graph data before import.
        """
        from archgraph.api import ArchGraph
        ag = ArchGraph(
            neo4j_uri=self._store._uri,
            neo4j_user=self._store._user,
            neo4j_password=self._store._password,
            neo4j_database=self._store._database,
        )
        try:
            return ag.extract(repo, languages=languages, clear_db=clear_db)
        finally:
            ag.close()

    @tool_method(
        description=(
            "Search for symbols (functions, classes, structs, etc.) by name, type, or file pattern. "
            "No Cypher knowledge needed."
        ),
        returns="list of matching symbols with id, name, labels, file, line",
    )
    def search(
        self,
        name: str = "",
        type: str = "",
        file_pattern: str = "",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search for symbols by name, type, or file pattern.

        Args:
            name: Symbol name (supports * wildcards for partial match).
            type: Filter by type (function, class, struct, interface, enum, module, file).
            file_pattern: Filter by file path pattern (supports * wildcards).
            limit: Max results (default 20).
        """
        from archgraph.api import ArchGraph
        ag = ArchGraph(
            neo4j_uri=self._store._uri,
            neo4j_user=self._store._user,
            neo4j_password=self._store._password,
            neo4j_database=self._store._database,
        )
        try:
            return ag.search(name=name, type=type, file_pattern=file_pattern, limit=limit)
        finally:
            ag.close()

    @tool_method(
        description="List all repositories that have been extracted and indexed",
        returns="list of repo dicts with name, path, languages, node/edge counts",
    )
    def repos(self) -> list[dict[str, Any]]:
        """List all extracted repositories."""
        from archgraph.api import ArchGraph
        return ArchGraph().repos()

    @tool_method(
        description=(
            "Search call relationships between functions. Find who calls a function "
            "or what a function calls. Supports call chain traversal."
        ),
        returns="list of call edges with caller, target, file, resolved status",
    )
    def search_calls(
        self,
        caller: str = "",
        target: str = "",
        file: str = "",
        resolved_only: bool = False,
        max_depth: int = 1,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search call relationships between functions.

        Args:
            caller: Caller function name (partial match).
            target: Target function name (partial match).
            file: Filter by file path (partial match).
            resolved_only: Only show SCIP-resolved calls.
            max_depth: Call chain depth (1=direct, >1=transitive).
            limit: Max results (default 20).
        """
        from archgraph.api import ArchGraph
        ag = ArchGraph(
            neo4j_uri=self._store._uri,
            neo4j_user=self._store._user,
            neo4j_password=self._store._password,
            neo4j_database=self._store._database,
        )
        try:
            return ag.search_calls(
                caller=caller, target=target, file=file,
                resolved_only=resolved_only, max_depth=max_depth, limit=limit,
            )
        finally:
            ag.close()

    def find_vulnerabilities(
        self, severity: str | None = None
    ) -> list[dict[str, Any]]:
        """Find known vulnerabilities affecting project dependencies.

        Args:
            severity: Optional severity filter substring (e.g. "CRITICAL", "HIGH").

        Returns:
            List of dicts with dependency name, vuln_id, summary, severity.
        """
        cypher = (
            "MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability) "
            "RETURN d.name AS dependency, d.version AS version, "
            "v.vuln_id AS vuln_id, v.summary AS summary, v.severity AS severity"
        )
        results = self.query(cypher)
        if severity:
            results = [r for r in results if severity.upper() in (r.get("severity") or "").upper()]
        return results

    def diff_summary(
        self,
        repo_path: str,
        languages: list[str] | None = None,
    ) -> dict[str, Any]:
        """Compare the current repo state against the stored Neo4j graph.

        Args:
            repo_path: Path to the local repository.
            languages: List of languages to extract (default: c,cpp,rust,java,go).

        Returns:
            Dict with nodes_added/removed/modified and edges_added/removed counts.
        """
        from pathlib import Path

        from archgraph.config import ExtractConfig
        from archgraph.graph.builder import GraphBuilder

        self._ensure_connected()

        config = ExtractConfig(
            repo_path=Path(repo_path),
            languages=languages or ["c", "cpp", "rust", "java", "go"],
            include_git=True,
            include_deps=True,
            include_annotations=True,
            include_security_labels=True,
        )

        current_graph = GraphBuilder(config).build()
        stored_graph = self._store.load_graph()
        graph_diff = stored_graph.diff(current_graph)
        return graph_diff.summary()


def create_tool(**kwargs: Any) -> ArchGraphTool:
    """Factory function for entry-point registration."""
    return ArchGraphTool(**kwargs)

