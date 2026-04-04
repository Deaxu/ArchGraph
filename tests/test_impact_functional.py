"""Functional tests for archgraph.tool.impact.ImpactAnalyzer.

Tests blast-radius analysis and change-impact with mocked Neo4j store.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, call
from typing import Any

from archgraph.tool.impact import ImpactAnalyzer

pytestmark = [pytest.mark.core]


# ===================================================================== #
# Helpers
# ===================================================================== #

def _make_analyzer(query_map: dict[str, list[dict[str, Any]]]) -> ImpactAnalyzer:
    """Create analyzer with a mock store.

    ``query_map`` maps a *substring* of the Cypher query to the
    list of records the mock should return for that query.  The first
    matching key wins; unmatched queries return ``[]``.
    """
    store = MagicMock()

    def mock_query(cypher: str, params: Any = None) -> list[dict[str, Any]]:
        for key, result in query_map.items():
            if key in cypher:
                return result
        return []

    store.query.side_effect = mock_query
    return ImpactAnalyzer(store)


# ===================================================================== #
# ImpactAnalyzer.analyze_impact
# ===================================================================== #

class TestAnalyzeImpact:
    """Tests for single-symbol impact analysis."""

    def test_downstream_returns_callees(self):
        """Downstream direction should traverse CALLS* forward."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:helper:5", "name": "helper", "file": "b.c",
                 "depth": 1, "sources": ["scip"]},
                {"id": "func:c.c:util:10", "name": "util", "file": "c.c",
                 "depth": 2, "sources": ["scip", "heuristic"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:main:1", direction="downstream")
        assert result["symbol"] == "func:a.c:main:1"
        assert result["direction"] == "downstream"
        assert result["total_affected"] == 2
        # depth-1 entry goes into 'immediate'
        assert any(e["name"] == "helper" for e in result["immediate"])
        # depth-2 entry goes into 'downstream'
        assert any(e["name"] == "util" for e in result["downstream"])

    def test_upstream_returns_callers(self):
        """Upstream direction should traverse CALLS* backward."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:x.c:caller:1", "name": "caller", "file": "x.c",
                 "depth": 1, "sources": ["scip"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:target:1", direction="upstream")
        assert result["direction"] == "upstream"
        assert result["total_affected"] == 1
        assert result["immediate"][0]["name"] == "caller"

    def test_both_direction(self):
        """Direction 'both' should include callers AND callees.

        The mock matches on 'CALLS*' for both queries, so we return the
        combined list for each; the test mainly verifies that the method
        runs both branches and sums up correctly.
        """
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:callee:5", "name": "callee", "file": "b.c",
                 "depth": 1, "sources": ["scip"]},
                {"id": "func:c.c:caller:10", "name": "caller", "file": "c.c",
                 "depth": 1, "sources": ["scip"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:center:1", direction="both")
        assert result["direction"] == "both"
        # Both queries matched so results are doubled (same mock for both)
        assert result["total_affected"] >= 2

    def test_empty_graph_returns_zero_affected(self):
        """No callers/callees should give total_affected == 0."""
        analyzer = _make_analyzer({"CALLS*": []})
        result = analyzer.analyze_impact("func:a.c:isolated:1", direction="both")
        assert result["total_affected"] == 0
        assert result["immediate"] == []
        assert result["downstream"] == []
        assert result["transitive"] == []

    # ------------------------------------------------------------------ #
    # Confidence scoring
    # ------------------------------------------------------------------ #

    def test_confidence_all_scip_is_high(self):
        """All edges from SCIP should produce 'high' resolution confidence."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:f1:5", "name": "f1", "file": "b.c",
                 "depth": 1, "sources": ["scip"]},
                {"id": "func:c.c:f2:10", "name": "f2", "file": "c.c",
                 "depth": 2, "sources": ["scip"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:t:1", direction="downstream")
        assert result["resolution_confidence"] == "high"
        assert result["resolution_stats"]["scip_edges"] == 2
        assert result["resolution_stats"]["heuristic_edges"] == 0

    def test_confidence_all_heuristic_is_low(self):
        """All edges from heuristic should produce 'low' confidence."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:f1:5", "name": "f1", "file": "b.c",
                 "depth": 1, "sources": ["heuristic"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:t:1", direction="upstream")
        assert result["resolution_confidence"] == "low"

    def test_confidence_mixed_is_medium(self):
        """Mix of SCIP and heuristic edges should produce 'medium' confidence."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:f1:5", "name": "f1", "file": "b.c",
                 "depth": 1, "sources": ["scip"]},
                {"id": "func:c.c:f2:10", "name": "f2", "file": "c.c",
                 "depth": 2, "sources": ["heuristic"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:t:1", direction="downstream")
        assert result["resolution_confidence"] == "medium"

    def test_confidence_no_edges_is_unknown(self):
        """No edges should produce 'unknown' resolution confidence."""
        analyzer = _make_analyzer({"CALLS*": []})
        result = analyzer.analyze_impact("func:a.c:t:1", direction="upstream")
        assert result["resolution_confidence"] == "unknown"

    # ------------------------------------------------------------------ #
    # Per-entry confidence
    # ------------------------------------------------------------------ #

    def test_entry_confidence_scip_only(self):
        """Individual entry with only SCIP sources should have 'high' confidence."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:f:5", "name": "f", "file": "b.c",
                 "depth": 1, "sources": ["scip"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:t:1", direction="downstream")
        assert result["immediate"][0]["confidence"] == "high"

    def test_entry_confidence_heuristic_only(self):
        """Individual entry with only heuristic sources should have 'low' confidence."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:f:5", "name": "f", "file": "b.c",
                 "depth": 1, "sources": ["heuristic"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:t:1", direction="downstream")
        assert result["immediate"][0]["confidence"] == "low"

    def test_entry_confidence_mixed(self):
        """Individual entry with both scip and heuristic should have 'medium'."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:f:5", "name": "f", "file": "b.c",
                 "depth": 1, "sources": ["scip", "heuristic"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:t:1", direction="downstream")
        assert result["immediate"][0]["confidence"] == "medium"

    # ------------------------------------------------------------------ #
    # Depth grouping
    # ------------------------------------------------------------------ #

    def test_depth_grouping(self):
        """Entries should be grouped by depth: 1 → immediate, 2 → downstream, 3+ → transitive."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "d1", "name": "d1", "file": "a.c", "depth": 1, "sources": ["scip"]},
                {"id": "d2", "name": "d2", "file": "b.c", "depth": 2, "sources": ["scip"]},
                {"id": "d3", "name": "d3", "file": "c.c", "depth": 3, "sources": ["scip"]},
                {"id": "d5", "name": "d5", "file": "d.c", "depth": 5, "sources": ["scip"]},
            ],
        })
        result = analyzer.analyze_impact("func:x:t:1", direction="downstream")
        assert len(result["immediate"]) == 1
        assert result["immediate"][0]["id"] == "d1"
        assert len(result["downstream"]) == 1
        assert result["downstream"][0]["id"] == "d2"
        assert len(result["transitive"]) == 2
        assert {e["id"] for e in result["transitive"]} == {"d3", "d5"}

    # ------------------------------------------------------------------ #
    # Result structure
    # ------------------------------------------------------------------ #

    def test_result_structure(self):
        """Impact result must have all required top-level fields."""
        analyzer = _make_analyzer({"CALLS*": []})
        result = analyzer.analyze_impact("func:a.c:foo:1")
        assert "symbol" in result
        assert "direction" in result
        assert "immediate" in result
        assert "downstream" in result
        assert "transitive" in result
        assert "total_affected" in result
        assert "resolution_confidence" in result
        assert "resolution_stats" in result
        assert "security_flags" in result

    def test_resolution_stats_structure(self):
        """resolution_stats must have scip_edges, heuristic_edges, unknown_edges."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "f1", "name": "f1", "file": "a.c", "depth": 1,
                 "sources": ["scip", "unknown_source"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:t:1", direction="downstream")
        stats = result["resolution_stats"]
        assert "scip_edges" in stats
        assert "heuristic_edges" in stats
        assert "unknown_edges" in stats
        assert stats["scip_edges"] == 1
        assert stats["heuristic_edges"] == 0
        assert stats["unknown_edges"] == 1  # 'unknown_source' is neither scip nor heuristic

    # ------------------------------------------------------------------ #
    # Security flags
    # ------------------------------------------------------------------ #

    def test_security_flags_uses_properties_key(self):
        """_check_security_flags looks for result['properties'] dict.

        The Cypher query results from _analyze_from_store return flat
        fields (id, name, file, depth, sources) without a 'properties'
        key, so security_flags will be empty for standard query results.
        This test documents the actual behavior.
        """
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:recv:5", "name": "recv", "file": "b.c",
                 "depth": 1, "sources": ["scip"]},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:main:1", direction="downstream")
        # No security properties on the result → flags should be empty
        assert result["security_flags"] == []

    def test_security_flags_from_flat_properties(self):
        """Security flags should be detected from flat query result properties."""
        analyzer = _make_analyzer({
            "CALLS*": [
                {"id": "func:b.c:recv:5", "name": "recv", "file": "b.c",
                 "depth": 1, "sources": ["scip"],
                 "is_input_source": True},
            ],
        })
        result = analyzer.analyze_impact("func:a.c:main:1", direction="downstream")
        assert len(result["security_flags"]) > 0
        assert any("input_source" in f for f in result["security_flags"])

    # ------------------------------------------------------------------ #
    # Error handling
    # ------------------------------------------------------------------ #

    def test_no_store_raises_runtime_error(self):
        """Calling analyze_impact without a store should raise RuntimeError."""
        analyzer = ImpactAnalyzer(store=None)
        with pytest.raises(RuntimeError, match="requires a Neo4jStore"):
            analyzer.analyze_impact("func:a.c:foo:1")


# ===================================================================== #
# ImpactAnalyzer.analyze_change_impact
# ===================================================================== #

class TestChangeImpact:
    """Test file-change impact analysis."""

    def _make_change_analyzer(
        self,
        changed_funcs: list[dict],
        affected_clusters: list[dict] | None = None,
        affected_processes: list[dict] | None = None,
        security_risks: list[dict] | None = None,
    ) -> ImpactAnalyzer:
        """Create analyzer for change-impact tests.

        Maps Cypher query substrings to return values.
        """
        store = MagicMock()

        def mock_query(cypher: str, params: Any = None) -> list[dict]:
            if "f.file IN" in cypher and "is_input" in cypher:
                return changed_funcs
            if "BELONGS_TO" in cypher:
                return affected_clusters or []
            if "PARTICIPATES_IN" in cypher:
                return affected_processes or []
            if "is_dangerous_sink" in cypher:
                return security_risks or []
            return []

        store.query.side_effect = mock_query
        return ImpactAnalyzer(store)

    def test_changed_files_finds_functions(self):
        """Functions in changed files should be listed."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "func:auth.c:validate:10", "name": "validate",
                 "file": "auth.c", "is_input": False, "is_sink": True},
            ],
        )
        result = analyzer.analyze_change_impact(["auth.c"])
        assert len(result["changed_functions"]) == 1
        assert result["changed_functions"][0]["name"] == "validate"

    def test_result_has_all_fields(self):
        """Change impact result must have all required fields."""
        analyzer = self._make_change_analyzer(changed_funcs=[])
        result = analyzer.analyze_change_impact(["foo.c"])
        assert "changed_files" in result
        assert "changed_functions" in result
        assert "affected_clusters" in result
        assert "affected_processes" in result
        assert "security_risks" in result
        assert "risk_level" in result
        assert result["changed_files"] == ["foo.c"]

    # ------------------------------------------------------------------ #
    # Risk level assessment
    # ------------------------------------------------------------------ #

    def test_risk_critical_when_source_and_sink(self):
        """CRITICAL when both input source and dangerous sink in changed funcs."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "f1", "name": "recv", "file": "net.c",
                 "is_input": True, "is_sink": False},
                {"id": "f2", "name": "exec", "file": "net.c",
                 "is_input": False, "is_sink": True},
            ],
        )
        result = analyzer.analyze_change_impact(["net.c"])
        assert result["risk_level"] == "CRITICAL"

    def test_risk_high_when_only_sink(self):
        """HIGH when a dangerous sink is changed but no input source."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "f1", "name": "exec_cmd", "file": "exec.c",
                 "is_input": False, "is_sink": True},
            ],
        )
        result = analyzer.analyze_change_impact(["exec.c"])
        assert result["risk_level"] == "HIGH"

    def test_risk_high_when_many_sink_reaches(self):
        """HIGH when changed code reaches >3 sinks transitively."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "f1", "name": "handler", "file": "api.c",
                 "is_input": False, "is_sink": False},
            ],
            security_risks=[
                {"id": f"sink{i}", "sink_name": f"sink{i}"} for i in range(4)
            ],
        )
        result = analyzer.analyze_change_impact(["api.c"])
        assert result["risk_level"] == "HIGH"

    def test_risk_medium_when_only_input_source(self):
        """MEDIUM when only input source (no sink) is changed."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "f1", "name": "read_input", "file": "io.c",
                 "is_input": True, "is_sink": False},
            ],
        )
        result = analyzer.analyze_change_impact(["io.c"])
        assert result["risk_level"] == "MEDIUM"

    def test_risk_medium_when_some_sink_reaches(self):
        """MEDIUM when sink_reach is between 1 and 3."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "f1", "name": "process", "file": "proc.c",
                 "is_input": False, "is_sink": False},
            ],
            security_risks=[
                {"id": "s1", "sink_name": "system"},
            ],
        )
        result = analyzer.analyze_change_impact(["proc.c"])
        assert result["risk_level"] == "MEDIUM"

    def test_risk_low_for_safe_changes(self):
        """LOW for changes to non-security functions with no sink reach."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "f1", "name": "format_date", "file": "util.c",
                 "is_input": False, "is_sink": False},
            ],
        )
        result = analyzer.analyze_change_impact(["util.c"])
        assert result["risk_level"] == "LOW"

    # ------------------------------------------------------------------ #
    # Clusters and processes
    # ------------------------------------------------------------------ #

    def test_affected_clusters_included(self):
        """Clusters linked to changed functions should appear in results."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "f1", "name": "parse", "file": "parser.c",
                 "is_input": False, "is_sink": False},
            ],
            affected_clusters=[
                {"id": "cluster:parsing", "name": "parsing", "cohesion": 0.85},
            ],
        )
        result = analyzer.analyze_change_impact(["parser.c"])
        assert len(result["affected_clusters"]) == 1
        assert result["affected_clusters"][0]["name"] == "parsing"

    def test_affected_processes_included(self):
        """Processes linked to changed functions should appear in results."""
        analyzer = self._make_change_analyzer(
            changed_funcs=[
                {"id": "f1", "name": "handle_request", "file": "server.c",
                 "is_input": False, "is_sink": False},
            ],
            affected_processes=[
                {"id": "proc:http_handling", "name": "http_handling", "type": "request"},
            ],
        )
        result = analyzer.analyze_change_impact(["server.c"])
        assert len(result["affected_processes"]) == 1
        assert result["affected_processes"][0]["name"] == "http_handling"


# ===================================================================== #
# ImpactAnalyzer._edge_confidence (static method, directly testable)
# ===================================================================== #

class TestEdgeConfidence:
    """Unit tests for the static _edge_confidence method."""

    def test_empty_sources(self):
        assert ImpactAnalyzer._edge_confidence([]) == "unknown"

    def test_scip_only(self):
        assert ImpactAnalyzer._edge_confidence(["scip"]) == "high"

    def test_heuristic_only(self):
        assert ImpactAnalyzer._edge_confidence(["heuristic"]) == "low"

    def test_scip_and_heuristic(self):
        assert ImpactAnalyzer._edge_confidence(["scip", "heuristic"]) == "medium"

    def test_unknown_source_only(self):
        """Sources that are neither scip nor heuristic should give 'unknown'."""
        assert ImpactAnalyzer._edge_confidence(["tree-sitter"]) == "unknown"

    def test_scip_with_unknown(self):
        """scip + unknown source (no heuristic) should still be 'high'."""
        assert ImpactAnalyzer._edge_confidence(["scip", "tree-sitter"]) == "high"

    def test_heuristic_with_unknown(self):
        """heuristic + unknown source (no scip) should still be 'low'."""
        assert ImpactAnalyzer._edge_confidence(["heuristic", "tree-sitter"]) == "low"
