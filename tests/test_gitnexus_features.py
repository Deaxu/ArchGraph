"""Tests for GitNexus-inspired features: clustering, process tracing, impact, search."""

from __future__ import annotations

from pathlib import Path

import pytest

from archgraph.enrichment.clustering import ClusterEnricher
from archgraph.enrichment.process import ProcessTracer
from archgraph.graph.schema import GraphData, NodeLabel, EdgeType
from archgraph.registry import RepoRegistry, RepoEntry
from archgraph.search import HybridSearcher


class TestClustering:
    """Tests for ClusterEnricher."""

    def test_cluster_small_graph(self):
        """Clustering should work on a small function graph."""
        graph = GraphData()

        # Add function nodes
        graph.add_node("func:a:foo:1", NodeLabel.FUNCTION, name="foo", file="a.c")
        graph.add_node("func:a:bar:2", NodeLabel.FUNCTION, name="bar", file="a.c")
        graph.add_node("func:a:baz:3", NodeLabel.FUNCTION, name="baz", file="a.c")
        graph.add_node("func:b:qux:1", NodeLabel.FUNCTION, name="qux", file="b.c")
        graph.add_node("func:b:quux:2", NodeLabel.FUNCTION, name="quux", file="b.c")

        # Add CALLS edges (forming two clusters)
        graph.add_edge("func:a:foo:1", "func:a:bar:2", EdgeType.CALLS)
        graph.add_edge("func:a:bar:2", "func:a:baz:3", EdgeType.CALLS)
        graph.add_edge("func:a:baz:3", "func:a:foo:1", EdgeType.CALLS)
        graph.add_edge("func:b:qux:1", "func:b:quux:2", EdgeType.CALLS)

        enricher = ClusterEnricher()
        count = enricher.enrich(graph)

        # Should detect at least 1 cluster (the tightly connected a.c group)
        cluster_nodes = [n for n in graph.nodes if n.label == NodeLabel.CLUSTER]
        assert len(cluster_nodes) >= 1

        # Should have BELONGS_TO edges
        belongs_edges = [e for e in graph.edges if e.type == EdgeType.BELONGS_TO]
        assert len(belongs_edges) >= 2

    def test_cluster_too_few_functions(self):
        """Should skip clustering for < 3 functions."""
        graph = GraphData()
        graph.add_node("func:a:foo:1", NodeLabel.FUNCTION, name="foo", file="a.c")
        graph.add_node("func:a:bar:2", NodeLabel.FUNCTION, name="bar", file="a.c")

        enricher = ClusterEnricher()
        count = enricher.enrich(graph)

        assert count == 0

    def test_cluster_cohesion_score(self):
        """Cohesion should be between 0 and 1."""
        graph = GraphData()

        # Fully connected triangle
        for i in range(4):
            graph.add_node(f"func:a:f{i}:{i}", NodeLabel.FUNCTION, name=f"f{i}", file="a.c")

        graph.add_edge("func:a:f0:0", "func:a:f1:1", EdgeType.CALLS)
        graph.add_edge("func:a:f1:1", "func:a:f2:2", EdgeType.CALLS)
        graph.add_edge("func:a:f2:2", "func:a:f0:0", EdgeType.CALLS)
        graph.add_edge("func:a:f0:0", "func:a:f3:3", EdgeType.CALLS)

        enricher = ClusterEnricher()
        enricher.enrich(graph)

        cluster_nodes = [n for n in graph.nodes if n.label == NodeLabel.CLUSTER]
        for cluster in cluster_nodes:
            cohesion = cluster.properties.get("cohesion", 0)
            assert 0 <= cohesion <= 1


class TestProcessTracing:
    """Tests for ProcessTracer."""

    def test_trace_from_main(self):
        """Should trace execution flow from main."""
        graph = GraphData()

        graph.add_node("func:src:main:1", NodeLabel.FUNCTION, name="main", file="main.c", is_exported=True)
        graph.add_node("func:src:init:5", NodeLabel.FUNCTION, name="init", file="main.c")
        graph.add_node("func:src:process:10", NodeLabel.FUNCTION, name="process", file="main.c")
        graph.add_node("func:src:cleanup:20", NodeLabel.FUNCTION, name="cleanup", file="main.c")

        graph.add_edge("func:src:main:1", "func:src:init:5", EdgeType.CALLS)
        graph.add_edge("func:src:main:1", "func:src:process:10", EdgeType.CALLS)
        graph.add_edge("func:src:process:10", "func:src:cleanup:20", EdgeType.CALLS)

        tracer = ProcessTracer()
        count = tracer.enrich(graph)

        process_nodes = [n for n in graph.nodes if n.label == NodeLabel.PROCESS]
        assert len(process_nodes) >= 1

        # Should have PARTICIPATES_IN edges
        participates = [e for e in graph.edges if e.type == EdgeType.PARTICIPATES_IN]
        assert len(participates) >= 3  # main, init, process at least

    def test_classify_data_flow_process(self):
        """Should classify processes that touch input and sink as data_flow."""
        graph = GraphData()

        graph.add_node("func:src:main:1", NodeLabel.FUNCTION, name="main", file="main.c")
        graph.add_node("func:src:read:5", NodeLabel.FUNCTION, name="read", file="main.c", is_input_source=True)
        graph.add_node("func:src:exec:10", NodeLabel.FUNCTION, name="exec", file="main.c", is_dangerous_sink=True)

        graph.add_edge("func:src:main:1", "func:src:read:5", EdgeType.CALLS)
        graph.add_edge("func:src:read:5", "func:src:exec:10", EdgeType.CALLS)

        tracer = ProcessTracer()
        tracer.enrich(graph)

        process_nodes = [n for n in graph.nodes if n.label == NodeLabel.PROCESS]
        if process_nodes:
            assert process_nodes[0].properties.get("type") == "data_flow"


class TestRegistry:
    """Tests for RepoRegistry."""

    def test_register_and_list(self, tmp_path: Path):
        """Should register and list repos."""
        registry_path = tmp_path / "registry.json"
        registry = RepoRegistry(registry_path)

        entry = registry.register(
            tmp_path / "myproject",
            languages=["python", "rust"],
            stats={"node_count": 100, "edge_count": 200},
        )

        assert entry.name == "myproject"
        assert entry.node_count == 100

        entries = registry.list_repos()
        assert len(entries) == 1

    def test_unregister(self, tmp_path: Path):
        """Should unregister repos."""
        registry_path = tmp_path / "registry.json"
        registry = RepoRegistry(registry_path)

        registry.register(tmp_path / "proj1")
        registry.register(tmp_path / "proj2")

        assert len(registry.list_repos()) == 2

        registry.unregister("proj1")
        assert len(registry.list_repos()) == 1

    def test_persistence(self, tmp_path: Path):
        """Should persist to disk."""
        registry_path = tmp_path / "registry.json"
        registry = RepoRegistry(registry_path)
        registry.register(tmp_path / "myproject", languages=["go"])

        # New instance should load from disk
        registry2 = RepoRegistry(registry_path)
        entries = registry2.list_repos()
        assert len(entries) == 1
        assert entries[0].languages == ["go"]


class TestHybridSearch:
    """Tests for HybridSearcher."""

    def test_tokenization(self):
        """Should tokenize text."""
        searcher = HybridSearcher.__new__(HybridSearcher)
        tokens = searcher._tokenize("parse user data")
        assert "parse" in tokens
        assert "user" in tokens
        assert "data" in tokens
        assert "data" in tokens

    def test_snippet_extraction(self):
        """Should extract relevant snippet."""
        searcher = HybridSearcher.__new__(HybridSearcher)
        text = "This function parses user data from the input buffer and validates it before processing"
        snippet = searcher._get_snippet(text, ["parse", "user", "data"], max_len=50)
        assert "parse" in snippet.lower() or "user" in snippet.lower()


class TestSchemaExtensions:
    """Tests for new schema types."""

    def test_cluster_label_exists(self):
        """CLUSTER label should exist."""
        assert hasattr(NodeLabel, "CLUSTER")
        assert NodeLabel.CLUSTER == "Cluster"

    def test_process_label_exists(self):
        """PROCESS label should exist."""
        assert hasattr(NodeLabel, "PROCESS")
        assert NodeLabel.PROCESS == "Process"

    def test_belongs_to_edge_exists(self):
        """BELONGS_TO edge type should exist."""
        assert hasattr(EdgeType, "BELONGS_TO")
        assert EdgeType.BELONGS_TO == "BELONGS_TO"

    def test_participates_in_edge_exists(self):
        """PARTICIPATES_IN edge type should exist."""
        assert hasattr(EdgeType, "PARTICIPATES_IN")
        assert EdgeType.PARTICIPATES_IN == "PARTICIPATES_IN"


class TestImpactAnalyzer:
    """Tests for ImpactAnalyzer (unit tests without Neo4j)."""

    def test_calculate_confidence(self):
        """Confidence should be between 0 and 1."""
        from archgraph.tool.impact import ImpactAnalyzer

        analyzer = ImpactAnalyzer.__new__(ImpactAnalyzer)
        assert analyzer._calculate_confidence(0, 5) == 0.0
        assert analyzer._calculate_confidence(10, 5) > 0  # Should be positive
        assert 0 <= analyzer._calculate_confidence(3, 5) <= 1

    def test_assess_risk(self):
        """Risk assessment should categorize correctly."""
        from archgraph.tool.impact import ImpactAnalyzer

        analyzer = ImpactAnalyzer.__new__(ImpactAnalyzer)

        # Input + Sink = CRITICAL
        assert analyzer._assess_risk(
            [{"is_input": True, "is_sink": True}],
            []
        ) == "CRITICAL"
        
        # Input + some sinks = HIGH
        assert analyzer._assess_risk(
            [{"is_input": True, "is_sink": False}],
            [{"id": "x"}]
        ) in ("HIGH", "MEDIUM")

        # Sink only = HIGH
        assert analyzer._assess_risk(
            [{"is_input": False, "is_sink": True}],
            []
        ) == "HIGH"

        # Neither = LOW
        assert analyzer._assess_risk(
            [{"is_input": False, "is_sink": False}],
            []
        ) == "LOW"
