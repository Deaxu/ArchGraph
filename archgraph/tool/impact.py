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
                "WITH caller, length(path) AS depth "
                "RETURN caller._id AS id, caller.name AS name, "
                "caller.file AS file, depth "
                "ORDER BY depth, caller.name"
            ).format(depth=max_depth)
            callers = self._store.query(callers_cypher, {"id": symbol_id})
        else:
            callers = []

        if direction in ("downstream", "both"):
            # Find all callees up to max_depth
            callees_cypher = (
                "MATCH path = (source:_Node {{_id: $id}})-[:CALLS*1..{depth}]->(callee:Function) "
                "WITH callee, length(path) AS depth "
                "RETURN callee._id AS id, callee.name AS name, "
                "callee.file AS file, depth "
                "ORDER BY depth, callee.name"
            ).format(depth=max_depth)
            callees = self._store.query(callees_cypher, {"id": symbol_id})
        else:
            callees = []

        # Group by depth
        immediate: list[dict[str, Any]] = []
        downstream_1_2: list[dict[str, Any]] = []
        transitive: list[dict[str, Any]] = []

        for result in callers + callees:
            depth = result.get("depth", 1)
            entry = {"id": result["id"], "name": result.get("name", ""), "file": result.get("file", "")}
            if depth == 1:
                immediate.append(entry)
            elif depth <= 2:
                downstream_1_2.append(entry)
            else:
                transitive.append(entry)

        # Calculate confidence based on graph connectivity
        total = len(immediate) + len(downstream_1_2) + len(transitive)
        confidence = self._calculate_confidence(total, max_depth)

        # Check for security-sensitive impact
        security_flags = self._check_security_flags(callers + callees)

        return {
            "symbol": symbol_id,
            "direction": direction,
            "immediate": immediate,
            "downstream": downstream_1_2,
            "transitive": transitive,
            "total_affected": total,
            "confidence": confidence,
            "security_flags": security_flags,
        }

    def analyze_change_impact(
        self, changed_files: list[str]
    ) -> dict[str, Any]:
        """Analyze impact of file changes.

        Args:
            changed_files: List of changed file paths

        Returns:
            Dict with affected processes, clusters, and risk assessment
        """
        assert self._store is not None

        # Find functions in changed files
        funcs_cypher = (
            "MATCH (f:Function) "
            "WHERE f.file IN $files "
            "RETURN f._id AS id, f.name AS name, f.file AS file, "
            "f.is_input_source AS is_input, f.is_dangerous_sink AS is_sink"
        )
        changed_funcs = self._store.query(funcs_cypher, {"files": changed_files})

        # Find affected clusters
        clusters_cypher = (
            "MATCH (f:Function)-[:BELONGS_TO]->(c:Cluster) "
            "WHERE f.file IN $files "
            "RETURN DISTINCT c._id AS id, c.name AS name, c.cohesion AS cohesion"
        )
        affected_clusters = self._store.query(clusters_cypher, {"files": changed_files})

        # Find affected processes
        processes_cypher = (
            "MATCH (f:Function)-[:PARTICIPATES_IN]->(p:Process) "
            "WHERE f.file IN $files "
            "RETURN DISTINCT p._id AS id, p.name AS name, p.type AS type"
        )
        affected_processes = self._store.query(processes_cypher, {"files": changed_files})

        # Find potential security impact
        security_cypher = (
            "MATCH (f:Function)-[:CALLS*1..3]->(sink:Function {is_dangerous_sink: true}) "
            "WHERE f.file IN $files "
            "RETURN DISTINCT sink._id AS id, sink.name AS sink_name"
        )
        security_risks = self._store.query(security_cypher, {"files": changed_files})

        # Risk assessment
        risk_level = self._assess_risk(changed_funcs, security_risks)

        return {
            "changed_files": changed_files,
            "changed_functions": changed_funcs,
            "affected_clusters": affected_clusters,
            "affected_processes": affected_processes,
            "security_risks": security_risks,
            "risk_level": risk_level,
        }

    def _calculate_confidence(self, total: int, max_depth: int) -> float:
        """Calculate confidence score (0.0-1.0) based on coverage."""
        if total == 0:
            return 0.0
        # More connections = higher confidence (diminishing returns)
        base = min(total / (max_depth * 5), 1.0)
        return round(base, 2)

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
