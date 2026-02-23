"""rlm-agent BaseTool integration — exposes Cypher query interface over Neo4j code graph."""

from __future__ import annotations

import logging
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
- **Function**: name, file, line_start, is_exported, is_input_source, is_dangerous_sink, \
is_allocator, is_crypto, is_parser, is_unsafe, has_unsafe_block, has_transmute, \
has_force_unwrap, has_goroutine, has_channel_op, has_defer
- **Class**: name, file, line_start
- **Struct**: name, file, line_start
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
- **CALLS**: Function → Function (includes unresolved funcref: nodes)
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
        neo4j_password: str = "neo4j",
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

