"""rlm-agent BaseTool integration — exposes Cypher query interface."""

from __future__ import annotations

import logging
from typing import Any

from archgraph.graph.neo4j_store import Neo4jStore

logger = logging.getLogger(__name__)


class ArchGraphTool:
    """Source code graph database tool for rlm-agent.

    Provides Cypher query access to the code knowledge graph
    stored in Neo4j, including code structure, call chains,
    data flow, git history, and vulnerability patterns.

    Usage (standalone, without rlm-agent dependency):
        tool = ArchGraphTool(neo4j_uri="bolt://localhost:7687")
        tool.connect()
        results = tool.query("MATCH (f:Function) RETURN f.name LIMIT 10")
        tool.close()

    If rlm-agent is available, this can be registered as a BaseTool.
    """

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
        return (
            "Source code graph database — query code structure, call chains, "
            "data flow, git history, and vulnerabilities via Cypher"
        )

    def connect(self) -> None:
        """Connect to Neo4j."""
        self._store.connect()
        self._connected = True

    def close(self) -> None:
        """Close connection."""
        self._store.close()
        self._connected = False

    def __enter__(self) -> ArchGraphTool:
        self.connect()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _ensure_connected(self) -> None:
        if not self._connected:
            self.connect()

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a Cypher query against the code graph.

        Args:
            cypher: Cypher query string.
            params: Optional query parameters.

        Returns:
            List of result records as dicts.
        """
        self._ensure_connected()
        return self._store.query(cypher, params)

    def schema(self) -> dict[str, Any]:
        """Get graph schema — all node labels, relationship types, and their properties.

        Returns:
            Dict with 'node_labels', 'relationship_types', and 'property_keys'.
        """
        self._ensure_connected()
        return self._store.schema_info()

    def stats(self) -> dict[str, Any]:
        """Get statistics — node/edge counts per type.

        Returns:
            Dict with 'nodes' and 'edges' sub-dicts containing counts.
        """
        self._ensure_connected()
        return self._store.stats()

    # ── Convenience query methods for common patterns ───────────────────────

    def find_attack_surface(self, limit: int = 50) -> list[dict[str, Any]]:
        """Find functions that receive external input (attack surface)."""
        return self.query(
            "MATCH (f:Function {is_input_source: true}) "
            "RETURN f.name AS name, f.file AS file, f.line_start AS line "
            "ORDER BY f.name LIMIT $limit",
            params={"limit": limit},
        )

    def find_dangerous_paths(
        self, source_name: str, max_depth: int = 5
    ) -> list[dict[str, Any]]:
        """Find call paths from a source function to dangerous sinks."""
        return self.query(
            "MATCH path = (f:Function {name: $name})"
            "-[:CALLS*1..$depth]->(sink:Function {is_dangerous_sink: true}) "
            "RETURN [n IN nodes(path) | n.name] AS chain, "
            "sink.name AS sink_name, length(path) AS depth",
            params={"name": source_name, "depth": max_depth},
        )

    def find_security_fixes(self, limit: int = 50) -> list[dict[str, Any]]:
        """Find commits identified as security fixes."""
        return self.query(
            "MATCH (sf:SecurityFix)-[:FIXED_BY]->(c:Commit) "
            "RETURN c.hash AS hash, c.message AS message, c.date AS date "
            "ORDER BY c.date DESC LIMIT $limit",
            params={"limit": limit},
        )

    def find_high_churn_files(self, min_churn: int = 20, limit: int = 30) -> list[dict[str, Any]]:
        """Find files with high change frequency (potential bug hotspots)."""
        return self.query(
            "MATCH (f:File) WHERE f.churn_count >= $min_churn "
            "RETURN f.path AS path, f.churn_count AS churn, f.language AS language "
            "ORDER BY f.churn_count DESC LIMIT $limit",
            params={"min_churn": min_churn, "limit": limit},
        )

    def find_taint_paths(self, limit: int = 50) -> list[dict[str, Any]]:
        """Find taint propagation paths (input source → dangerous sink)."""
        return self.query(
            "MATCH (src)-[t:TAINTS]->(sink) "
            "RETURN src._id AS source, sink._id AS sink, "
            "t.via_function AS via_function, t.via_variable AS via_variable, "
            "t.file AS file "
            "LIMIT $limit",
            params={"limit": limit},
        )

    def find_function_cfg(self, func_name: str) -> list[dict[str, Any]]:
        """Get the control flow graph of a function (BasicBlock nodes + edges)."""
        return self.query(
            "MATCH (f:Function {name: $name})-[:CONTAINS]->(bb:BasicBlock) "
            "OPTIONAL MATCH (bb)-[:BRANCHES_TO]->(succ:BasicBlock) "
            "RETURN bb._id AS block, bb.block_index AS idx, "
            "bb.stmt_count AS stmts, collect(succ.block_index) AS successors "
            "ORDER BY bb.block_index",
            params={"name": func_name},
        )

    def find_data_flows(self, func_name: str) -> list[dict[str, Any]]:
        """Get data flow edges within a function."""
        return self.query(
            "MATCH (f:Function {name: $name})-[d:DATA_FLOWS_TO]->(f) "
            "RETURN d.from_var AS from_var, d.from_line AS from_line, "
            "d.to_var AS to_var, d.to_line AS to_line "
            "ORDER BY d.from_line",
            params={"name": func_name},
        )


    def find_unsafe_functions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Find functions with unsafe patterns (unsafe blocks, transmute, force unwrap, etc.)."""
        return self.query(
            "MATCH (f:Function) "
            "WHERE f.has_unsafe_block = true OR f.is_unsafe_fn = true "
            "OR f.has_transmute = true OR f.has_force_unwrap = true "
            "OR f.has_unsafe_pointer = true "
            "RETURN f.name AS name, f.file AS file, f.line_start AS line, "
            "f.has_unsafe_block AS unsafe_block, f.is_unsafe_fn AS unsafe_fn, "
            "f.has_transmute AS transmute, f.has_force_unwrap AS force_unwrap "
            "ORDER BY f.name LIMIT $limit",
            params={"limit": limit},
        )

    def find_goroutine_spawners(self, limit: int = 50) -> list[dict[str, Any]]:
        """Find Go functions that spawn goroutines."""
        return self.query(
            "MATCH (f:Function {has_goroutine: true}) "
            "RETURN f.name AS name, f.file AS file, f.line_start AS line, "
            "f.has_channel_op AS channel_op, f.has_defer AS has_defer "
            "ORDER BY f.name LIMIT $limit",
            params={"limit": limit},
        )


def create_tool(**kwargs: Any) -> ArchGraphTool:
    """Factory function to create and return an ArchGraphTool instance.

    This can be used as an entry point for tool registration.
    """
    return ArchGraphTool(**kwargs)
