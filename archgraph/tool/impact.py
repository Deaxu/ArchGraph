"""Impact analysis — blast radius computation for code changes."""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from archgraph.graph.neo4j_store import Neo4jStore
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

logger = logging.getLogger(__name__)


class ImpactAnalyzer:
    """Analyzes blast radius of changes using graph traversal."""

    def __init__(self, store: Neo4jStore | None = None) -> None:
        self._store = store

    def analyze_impact(
        self,
        symbol_id: str,
        direction: str = "upstream",
        max_depth: int = 5,
    ) -> dict[str, Any]:
        """Analyze impact of a symbol.

        Args:
            symbol_id: Node ID (e.g. "func:src/auth.c:validate:42")
            direction: "upstream" (callers), "downstream" (callees), or "both"
            max_depth: Maximum traversal depth

        Returns:
            Dict with impact analysis results
        """
        if self._store:
            return self._analyze_from_store(symbol_id, direction, max_depth)
        raise RuntimeError("ImpactAnalyzer requires a Neo4jStore connection")

    def _analyze_from_store(
        self, symbol_id: str, direction: str, max_depth: int
    ) -> dict[str, Any]:
        """Analyze impact using Neo4j graph queries."""
        assert self._store is not None

        if direction in ("upstream", "both"):
            # Find all callers up to max_depth (reverse CALLS)
            callers_cypher = (
                "MATCH path = (caller:Function)-[:CALLS*1..{depth}]->(target:_Node {{_id: $id}}) "
                "WITH caller, length(path) AS depth, "
                "[r IN relationships(path) | coalesce(r.source, 'unknown')] AS sources "
                "RETURN caller._id AS id, caller.name AS name, "
                "caller.file AS file, depth, sources "
                "ORDER BY depth, caller.name"
            ).format(depth=max_depth)
            callers = self._store.query(callers_cypher, {"id": symbol_id})
        else:
            callers = []

        if direction in ("downstream", "both"):
            # Find all callees up to max_depth
            callees_cypher = (
                "MATCH path = (source:_Node {{_id: $id}})-[:CALLS*1..{depth}]->(callee:Function) "
                "WITH callee, length(path) AS depth, "
                "[r IN relationships(path) | coalesce(r.source, 'unknown')] AS sources "
                "RETURN callee._id AS id, callee.name AS name, "
                "callee.file AS file, depth, sources "
                "ORDER BY depth, callee.name"
            ).format(depth=max_depth)
            callees = self._store.query(callees_cypher, {"id": symbol_id})
        else:
            callees = []

        # Group by depth and compute per-entry confidence
        immediate: list[dict[str, Any]] = []
        downstream_1_2: list[dict[str, Any]] = []
        transitive: list[dict[str, Any]] = []

        scip_count = 0
        heuristic_count = 0
        total_edges = 0

        for result in callers + callees:
            depth = result.get("depth", 1)
            sources = result.get("sources", [])
            entry_confidence = self._edge_confidence(sources)
            entry = {
                "id": result["id"],
                "name": result.get("name", ""),
                "file": result.get("file", ""),
                "confidence": entry_confidence,
            }
            if depth == 1:
                immediate.append(entry)
            elif depth <= 2:
                downstream_1_2.append(entry)
            else:
                transitive.append(entry)

            for s in sources:
                total_edges += 1
                if s == "scip":
                    scip_count += 1
                elif s == "heuristic":
                    heuristic_count += 1

        # Overall confidence based on edge resolution sources
        total = len(immediate) + len(downstream_1_2) + len(transitive)
        if total_edges == 0:
            resolution_confidence = "unknown"
        elif heuristic_count == 0:
            resolution_confidence = "high"
        elif scip_count == 0:
            resolution_confidence = "low"
        else:
            resolution_confidence = "medium"

        # Check for security-sensitive impact
        security_flags = self._check_security_flags(callers + callees)

        return {
            "symbol": symbol_id,
            "direction": direction,
            "immediate": immediate,
            "downstream": downstream_1_2,
            "transitive": transitive,
            "total_affected": total,
            "resolution_confidence": resolution_confidence,
            "resolution_stats": {
                "scip_edges": scip_count,
                "heuristic_edges": heuristic_count,
                "unknown_edges": total_edges - scip_count - heuristic_count,
            },
            "security_flags": security_flags,
        }

    def analyze_change_impact(
        self, changed_files: list[str], repo_name: str | None = None
    ) -> dict[str, Any]:
        """Analyze impact of file changes.

        Args:
            changed_files: List of changed file paths
            repo_name: Optional repository name to filter results

        Returns:
            Dict with affected processes, clusters, and risk assessment
        """
        assert self._store is not None

        repo_clause = " AND f.repo = $repo" if repo_name else ""
        params_base: dict[str, Any] = {"files": changed_files}
        if repo_name:
            params_base["repo"] = repo_name

        changed_funcs = self._store.query(
            f"MATCH (f:Function) WHERE f.file IN $files{repo_clause} "
            "RETURN f._id AS id, f.name AS name, f.file AS file, "
            "f.is_input_source AS is_input, f.is_dangerous_sink AS is_sink",
            params_base,
        )

        affected_clusters = self._store.query(
            f"MATCH (f:Function)-[:BELONGS_TO]->(c:Cluster) "
            f"WHERE f.file IN $files{repo_clause} "
            "RETURN DISTINCT c._id AS id, c.name AS name, c.cohesion AS cohesion",
            params_base,
        )

        affected_processes = self._store.query(
            f"MATCH (f:Function)-[:PARTICIPATES_IN]->(p:Process) "
            f"WHERE f.file IN $files{repo_clause} "
            "RETURN DISTINCT p._id AS id, p.name AS name, p.type AS type",
            params_base,
        )

        security_cypher = (
            f"MATCH (f:Function)-[:CALLS*1..3]->(sink:Function {{is_dangerous_sink: true}}) "
            f"WHERE f.file IN $files{repo_clause} "
            "RETURN DISTINCT sink._id AS id, sink.name AS sink_name"
        )
        security_risks = self._store.query(security_cypher, params_base)

        risk_level = self._assess_risk(changed_funcs, security_risks)

        return {
            "changed_files": changed_files,
            "changed_functions": changed_funcs,
            "affected_clusters": affected_clusters,
            "affected_processes": affected_processes,
            "security_risks": security_risks,
            "risk_level": risk_level,
        }

    @staticmethod
    def _edge_confidence(sources: list[str]) -> str:
        """Determine confidence level from edge sources along a path."""
        if not sources:
            return "unknown"
        has_heuristic = any(s == "heuristic" for s in sources)
        has_scip = any(s == "scip" for s in sources)
        if has_heuristic and not has_scip:
            return "low"
        if has_scip and not has_heuristic:
            return "high"
        if has_scip and has_heuristic:
            return "medium"
        return "unknown"

    def _check_security_flags(self, results: list[dict[str, Any]]) -> list[str]:
        """Check if any affected functions are security-sensitive."""
        flags: list[str] = []
        for r in results:
            props = r.get("properties", {})
            if props.get("is_input_source"):
                flags.append(f"input_source:{r.get('_id', r.get('id', ''))}")
            if props.get("is_dangerous_sink"):
                flags.append(f"dangerous_sink:{r.get('_id', r.get('id', ''))}")
            if props.get("is_crypto"):
                flags.append(f"crypto:{r.get('_id', r.get('id', ''))}")
        return flags

    def _assess_risk(
        self,
        changed_funcs: list[dict[str, Any]],
        security_risks: list[dict[str, Any]],
    ) -> str:
        """Assess overall risk level of changes."""
        has_input = any(f.get("is_input") for f in changed_funcs)
        has_sink = any(f.get("is_sink") for f in changed_funcs)
        sink_reach = len(security_risks)

        if has_input and has_sink:
            return "CRITICAL"
        if has_sink or sink_reach > 3:
            return "HIGH"
        if has_input or sink_reach > 0:
            return "MEDIUM"
        return "LOW"
