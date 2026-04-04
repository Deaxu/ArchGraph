"""Tests for archgraph/export.py — verify exported CONTENT matches the graph."""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from archgraph.export import export_csv, export_graphml, export_json
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

pytestmark = pytest.mark.core


@pytest.fixture
def sample_graph() -> GraphData:
    """Create a realistic graph for export testing."""
    graph = GraphData()
    graph.add_node(
        "file:src/main.c", NodeLabel.FILE, path="src/main.c", language="c", lines=50
    )
    graph.add_node(
        "func:src/main.c:main:1",
        NodeLabel.FUNCTION,
        name="main",
        file="src/main.c",
        line_start=1,
        line_end=10,
        is_exported=True,
    )
    graph.add_node(
        "func:src/main.c:helper:20",
        NodeLabel.FUNCTION,
        name="helper",
        file="src/main.c",
        line_start=20,
        line_end=30,
    )
    graph.add_node(
        "struct:src/main.c:Config:40",
        NodeLabel.STRUCT,
        name="Config",
        file="src/main.c",
    )
    graph.add_edge("file:src/main.c", "func:src/main.c:main:1", EdgeType.CONTAINS)
    graph.add_edge("file:src/main.c", "func:src/main.c:helper:20", EdgeType.CONTAINS)
    graph.add_edge("func:src/main.c:main:1", "func:src/main.c:helper:20", EdgeType.CALLS)
    return graph


# ── JSON export ──────────────────────────────────────────────────────────────


class TestExportJSON:
    def test_json_contains_all_nodes(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_json(sample_graph, tmp_path / "graph.json")
        data = json.loads(path.read_text())
        assert len(data["nodes"]) == 4

    def test_json_contains_all_edges(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_json(sample_graph, tmp_path / "graph.json")
        data = json.loads(path.read_text())
        assert len(data["edges"]) == 3

    def test_json_node_has_id_and_label(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_json(sample_graph, tmp_path / "graph.json")
        data = json.loads(path.read_text())
        for node in data["nodes"]:
            assert "id" in node
            assert "label" in node

    def test_json_node_properties_preserved(
        self, sample_graph: GraphData, tmp_path: Path
    ) -> None:
        path = export_json(sample_graph, tmp_path / "graph.json")
        data = json.loads(path.read_text())
        main_node = next(n for n in data["nodes"] if n["id"] == "func:src/main.c:main:1")
        assert main_node["name"] == "main"
        assert main_node["file"] == "src/main.c"
        assert main_node["line_start"] == 1
        assert main_node["line_end"] == 10
        assert main_node["is_exported"] is True

    def test_json_node_labels_correct(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_json(sample_graph, tmp_path / "graph.json")
        data = json.loads(path.read_text())
        labels = {n["id"]: n["label"] for n in data["nodes"]}
        assert labels["file:src/main.c"] == NodeLabel.FILE
        assert labels["func:src/main.c:main:1"] == NodeLabel.FUNCTION
        assert labels["struct:src/main.c:Config:40"] == NodeLabel.STRUCT

    def test_json_edge_has_source_target_type(
        self, sample_graph: GraphData, tmp_path: Path
    ) -> None:
        path = export_json(sample_graph, tmp_path / "graph.json")
        data = json.loads(path.read_text())
        for edge in data["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "type" in edge

    def test_json_edge_types_correct(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_json(sample_graph, tmp_path / "graph.json")
        data = json.loads(path.read_text())
        edge_types = {(e["source"], e["target"]): e["type"] for e in data["edges"]}
        assert edge_types[("file:src/main.c", "func:src/main.c:main:1")] == EdgeType.CONTAINS
        assert (
            edge_types[("func:src/main.c:main:1", "func:src/main.c:helper:20")] == EdgeType.CALLS
        )

    def test_json_has_stats(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_json(sample_graph, tmp_path / "graph.json")
        data = json.loads(path.read_text())
        assert "stats" in data
        stats = data["stats"]
        assert "nodes" in stats
        assert "edges" in stats
        # Stats should reflect label/type counts
        assert stats["nodes"][NodeLabel.FUNCTION] == 2
        assert stats["nodes"][NodeLabel.FILE] == 1
        assert stats["edges"][EdgeType.CONTAINS] == 2
        assert stats["edges"][EdgeType.CALLS] == 1

    def test_json_empty_graph(self, tmp_path: Path) -> None:
        """Exporting an empty graph should produce valid JSON with zero nodes/edges."""
        graph = GraphData()
        path = export_json(graph, tmp_path / "empty.json")
        data = json.loads(path.read_text())
        assert data["nodes"] == []
        assert data["edges"] == []
        assert data["stats"]["nodes"] == {}
        assert data["stats"]["edges"] == {}

    def test_json_round_trip_node_count(self, tmp_c_project: Path, tmp_path: Path) -> None:
        """Extract a real project and verify exported node count matches."""
        from archgraph.extractors.treesitter import TreeSitterExtractor

        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_c_project)
        path = export_json(graph, tmp_path / "real.json")
        data = json.loads(path.read_text())
        assert len(data["nodes"]) == graph.node_count
        assert len(data["edges"]) == graph.edge_count

    def test_json_round_trip_ids_match(self, tmp_c_project: Path, tmp_path: Path) -> None:
        """Node IDs in the exported JSON must match the original graph exactly."""
        from archgraph.extractors.treesitter import TreeSitterExtractor

        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_c_project)
        path = export_json(graph, tmp_path / "real.json")
        data = json.loads(path.read_text())
        original_ids = {n.id for n in graph.nodes}
        exported_ids = {n["id"] for n in data["nodes"]}
        assert original_ids == exported_ids

    def test_json_output_file_created(self, sample_graph: GraphData, tmp_path: Path) -> None:
        """export_json must return a Path that exists."""
        path = export_json(sample_graph, tmp_path / "out.json")
        assert path.exists()
        assert path.suffix == ".json"


# ── CSV export ───────────────────────────────────────────────────────────────


class TestExportCSV:
    def test_csv_creates_two_files(self, sample_graph: GraphData, tmp_path: Path) -> None:
        result = export_csv(sample_graph, tmp_path / "csv_out")
        assert "nodes" in result
        assert "edges" in result
        assert result["nodes"].exists()
        assert result["edges"].exists()

    def test_csv_nodes_has_header(self, sample_graph: GraphData, tmp_path: Path) -> None:
        result = export_csv(sample_graph, tmp_path / "csv_out")
        header = result["nodes"].read_text(encoding="utf-8").splitlines()[0]
        assert "id" in header
        assert "label" in header

    def test_csv_node_count_matches(self, sample_graph: GraphData, tmp_path: Path) -> None:
        result = export_csv(sample_graph, tmp_path / "csv_out")
        lines = result["nodes"].read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) - 1 == 4  # minus header

    def test_csv_edge_count_matches(self, sample_graph: GraphData, tmp_path: Path) -> None:
        result = export_csv(sample_graph, tmp_path / "csv_out")
        lines = result["edges"].read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) - 1 == 3  # minus header

    def test_csv_edges_header_has_source_target_type(
        self, sample_graph: GraphData, tmp_path: Path
    ) -> None:
        result = export_csv(sample_graph, tmp_path / "csv_out")
        header = result["edges"].read_text(encoding="utf-8").splitlines()[0]
        assert "source" in header
        assert "target" in header
        assert "type" in header

    def test_csv_node_ids_present(self, sample_graph: GraphData, tmp_path: Path) -> None:
        """All node IDs from the graph must appear in the CSV."""
        result = export_csv(sample_graph, tmp_path / "csv_out")
        content = result["nodes"].read_text(encoding="utf-8")
        reader = csv.DictReader(content.splitlines())
        csv_ids = {row["id"] for row in reader}
        graph_ids = {n.id for n in sample_graph.nodes}
        assert csv_ids == graph_ids

    def test_csv_edge_values_present(self, sample_graph: GraphData, tmp_path: Path) -> None:
        """Edge source/target/type values must be present in CSV."""
        result = export_csv(sample_graph, tmp_path / "csv_out")
        content = result["edges"].read_text(encoding="utf-8")
        reader = csv.DictReader(content.splitlines())
        edges = [(row["source"], row["target"], row["type"]) for row in reader]
        assert ("file:src/main.c", "func:src/main.c:main:1", EdgeType.CONTAINS) in edges
        assert (
            "func:src/main.c:main:1",
            "func:src/main.c:helper:20",
            EdgeType.CALLS,
        ) in edges

    def test_csv_empty_graph(self, tmp_path: Path) -> None:
        """Exporting an empty graph should produce CSV files with only headers."""
        graph = GraphData()
        result = export_csv(graph, tmp_path / "csv_empty")
        node_lines = result["nodes"].read_text(encoding="utf-8").strip().splitlines()
        edge_lines = result["edges"].read_text(encoding="utf-8").strip().splitlines()
        assert len(node_lines) == 1  # header only
        assert len(edge_lines) == 1  # header only

    def test_csv_node_property_columns(self, sample_graph: GraphData, tmp_path: Path) -> None:
        """CSV columns should include property keys from nodes."""
        result = export_csv(sample_graph, tmp_path / "csv_out")
        header = result["nodes"].read_text(encoding="utf-8").splitlines()[0]
        # Properties like 'name', 'path', 'language' should be columns
        assert "name" in header
        assert "path" in header
        assert "language" in header


# ── GraphML export ───────────────────────────────────────────────────────────

_GRAPHML_NS = "http://graphml.graphdrawing.org/xmlns"


class TestExportGraphML:
    def test_graphml_valid_xml(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_graphml(sample_graph, tmp_path / "graph.graphml")
        tree = ET.parse(path)
        assert tree.getroot() is not None

    def test_graphml_node_count(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_graphml(sample_graph, tmp_path / "graph.graphml")
        tree = ET.parse(path)
        nodes = tree.findall(f".//{{{_GRAPHML_NS}}}node")
        assert len(nodes) == 4

    def test_graphml_edge_count(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_graphml(sample_graph, tmp_path / "graph.graphml")
        tree = ET.parse(path)
        edges = tree.findall(f".//{{{_GRAPHML_NS}}}edge")
        assert len(edges) == 3

    def test_graphml_node_ids_match(self, sample_graph: GraphData, tmp_path: Path) -> None:
        """Node IDs in GraphML must match original graph."""
        path = export_graphml(sample_graph, tmp_path / "graph.graphml")
        tree = ET.parse(path)
        xml_ids = {n.get("id") for n in tree.findall(f".//{{{_GRAPHML_NS}}}node")}
        graph_ids = {n.id for n in sample_graph.nodes}
        assert xml_ids == graph_ids

    def test_graphml_edge_endpoints_match(self, sample_graph: GraphData, tmp_path: Path) -> None:
        """Edge source/target in GraphML must correspond to the graph edges."""
        path = export_graphml(sample_graph, tmp_path / "graph.graphml")
        tree = ET.parse(path)
        xml_edges = {
            (e.get("source"), e.get("target"))
            for e in tree.findall(f".//{{{_GRAPHML_NS}}}edge")
        }
        graph_edges = {(e.source_id, e.target_id) for e in sample_graph.edges}
        assert xml_edges == graph_edges

    def test_graphml_output_file_created(self, sample_graph: GraphData, tmp_path: Path) -> None:
        path = export_graphml(sample_graph, tmp_path / "out.graphml")
        assert path.exists()

    def test_graphml_empty_graph(self, tmp_path: Path) -> None:
        """Exporting an empty graph should produce a valid GraphML with zero nodes."""
        graph = GraphData()
        path = export_graphml(graph, tmp_path / "empty.graphml")
        tree = ET.parse(path)
        nodes = tree.findall(f".//{{{_GRAPHML_NS}}}node")
        edges = tree.findall(f".//{{{_GRAPHML_NS}}}edge")
        assert len(nodes) == 0
        assert len(edges) == 0
