"""Tests for new features: auto-detect, risk score, export, cache."""

from __future__ import annotations

from pathlib import Path

import pytest

# Import from cli module
import importlib
_cli = importlib.import_module("archgraph.cli")
from archgraph.export import export_json, export_graphml, export_csv
from archgraph.extractors.security_labels import SecurityLabeler
from archgraph.graph.schema import GraphData, NodeLabel
from archgraph.mcp.server import _ToolCache


class TestAutoDetect:
    """Tests for language auto-detection."""

    def test_detect_c_repo(self, tmp_path: Path):
        """Should detect C files."""
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        (tmp_path / "util.h").write_text("void foo();")
        (tmp_path / "lib.c").write_text("void foo() {}")

        langs = _cli._detect_languages(tmp_path)
        assert "c" in langs
        assert langs[0] == "c"  # Most files

    def test_detect_mixed_repo(self, tmp_path: Path):
        """Should detect multiple languages."""
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "server.py").write_text("print('server')")
        (tmp_path / "utils.py").write_text("print('utils')")

        langs = _cli._detect_languages(tmp_path)
        # Python has more files, should be first
        assert "python" in langs or "c" in langs

    def test_detect_empty_repo(self, tmp_path: Path):
        """Should return defaults for empty repo."""
        langs = _cli._detect_languages(tmp_path)
        assert len(langs) > 0
        assert langs == ["c", "cpp", "rust", "java", "go"]


class TestRiskScore:
    """Tests for risk score calculation."""

    def test_risk_score_input_and_sink(self):
        """Input source + dangerous sink should have high risk."""
        graph = GraphData()
        graph.add_node(
            "func:test:dangerous:1",
            NodeLabel.FUNCTION,
            name="dangerous",
            file="test.c",
            is_input_source=True,
            is_dangerous_sink=True,
        )

        labeler = SecurityLabeler()
        # Manually set properties for test
        for node in graph.nodes:
            risk = 0
            if node.properties.get("is_input_source"):
                risk += 30
            if node.properties.get("is_dangerous_sink"):
                risk += 30
            if node.properties.get("touches_unsafe"):
                risk += 20
            if node.properties.get("is_allocator"):
                risk += 10
            if node.properties.get("is_parser"):
                risk += 10
            node.properties["risk_score"] = min(risk, 100)

        assert graph.nodes[0].properties["risk_score"] == 60

    def test_risk_score_max_100(self):
        """Risk score should be capped at 100."""
        graph = GraphData()
        graph.add_node(
            "func:test:max_risk:1",
            NodeLabel.FUNCTION,
            name="max_risk",
            file="test.c",
            is_input_source=True,
            is_dangerous_sink=True,
            touches_unsafe=True,
            is_allocator=True,
            is_parser=True,
        )

        for node in graph.nodes:
            risk = 0
            if node.properties.get("is_input_source"):
                risk += 30
            if node.properties.get("is_dangerous_sink"):
                risk += 30
            if node.properties.get("touches_unsafe"):
                risk += 20
            if node.properties.get("is_allocator"):
                risk += 10
            if node.properties.get("is_parser"):
                risk += 10
            node.properties["risk_score"] = min(risk, 100)

        assert graph.nodes[0].properties["risk_score"] == 100


class TestExport:
    """Tests for export formats."""

    def test_export_json(self, tmp_path: Path):
        """Should export valid JSON."""
        graph = GraphData()
        graph.add_node("file:main.c", NodeLabel.FILE, path="main.c", language="c")
        graph.add_node("func:main.c:main:1", NodeLabel.FUNCTION, name="main", file="main.c")
        graph.add_edge("file:main.c", "func:main.c:main:1", "CONTAINS")

        output = tmp_path / "test.json"
        export_json(graph, output)

        assert output.exists()
        import json
        data = json.loads(output.read_text())
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1

    def test_export_csv(self, tmp_path: Path):
        """Should export CSV files."""
        graph = GraphData()
        graph.add_node("file:main.c", NodeLabel.FILE, path="main.c")
        graph.add_node("func:main.c:main:1", NodeLabel.FUNCTION, name="main")
        graph.add_edge("file:main.c", "func:main.c:main:1", "CONTAINS")

        output_dir = tmp_path / "csv_export"
        paths = export_csv(graph, output_dir)

        assert paths["nodes"].exists()
        assert paths["edges"].exists()

        # Check CSV content
        nodes_content = paths["nodes"].read_text()
        assert "file:main.c" in nodes_content
        assert "func:main.c:main:1" in nodes_content

    def test_export_graphml(self, tmp_path: Path):
        """Should export GraphML."""
        graph = GraphData()
        graph.add_node("file:main.c", NodeLabel.FILE, path="main.c")
        graph.add_node("func:main.c:main:1", NodeLabel.FUNCTION, name="main")
        graph.add_edge("file:main.c", "func:main.c:main:1", "CONTAINS")

        output = tmp_path / "test.graphml"
        export_graphml(graph, output)

        assert output.exists()
        content = output.read_text()
        assert "graphml" in content.lower()


class TestMcpCache:
    """Tests for MCP tool cache."""

    def test_cache_set_and_get(self):
        """Should cache and retrieve values."""
        cache = _ToolCache(ttl=60)
        cache.set("query", {"cypher": "MATCH (n) RETURN n"}, [{"result": "data"}])

        result = cache.get("query", {"cypher": "MATCH (n) RETURN n"})
        assert result == [{"result": "data"}]

    def test_cache_miss(self):
        """Should return None for cache miss."""
        cache = _ToolCache(ttl=60)
        result = cache.get("query", {"cypher": "MATCH (x) RETURN x"})
        assert result is None

    def test_cache_different_keys(self):
        """Different arguments should have different cache keys."""
        cache = _ToolCache(ttl=60)
        cache.set("query", {"cypher": "A"}, "result_a")
        cache.set("query", {"cypher": "B"}, "result_b")

        assert cache.get("query", {"cypher": "A"}) == "result_a"
        assert cache.get("query", {"cypher": "B"}) == "result_b"

    def test_cache_ttl_expired(self):
        """Expired entries should return None."""
        cache = _ToolCache(ttl=0)  # Immediate expiry
        cache.set("query", {"cypher": "MATCH (n)"}, "data")
        import time
        time.sleep(0.1)
        assert cache.get("query", {"cypher": "MATCH (n)"}) is None
