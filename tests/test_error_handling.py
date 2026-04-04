"""Tests for error handling across the system — verify graceful degradation on bad input."""

from __future__ import annotations

from pathlib import Path

import pytest

from archgraph.config import ExtractConfig
from archgraph.extractors.annotations import AnnotationExtractor
from archgraph.extractors.dependencies import DependencyExtractor
from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel
from archgraph.manifest import scan_current_files

pytestmark = pytest.mark.core


# ── Extractor error handling ─────────────────────────────────────────────────


class TestTreeSitterErrors:
    """Test TreeSitterExtractor handles bad input gracefully."""

    def test_empty_dir(self, tmp_path: Path) -> None:
        """Empty directory should return empty graph, not crash."""
        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_binary_file_skipped(self, tmp_path: Path) -> None:
        """Binary files should be skipped without crashing."""
        (tmp_path / "binary.c").write_bytes(b"\x00\x01\x02\x03" * 100)
        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_path)
        # Should not crash; may produce a file node but not function nodes from garbage
        assert isinstance(graph, GraphData)

    def test_syntax_error_tolerance(self, tmp_path: Path) -> None:
        """Files with syntax errors should not crash the extractor."""
        (tmp_path / "bad.c").write_text("void { broken syntax {{{{ }}}}")
        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_path)
        # Should produce at least a file node; tree-sitter is error-tolerant
        assert isinstance(graph, GraphData)
        assert graph.node_count >= 0

    def test_huge_file_handled(self, tmp_path: Path) -> None:
        """Very large files should be handled (possibly skipped if over max_file_size)."""
        lines = [f"void func_{i}(void) {{ return; }}" for i in range(10000)]
        (tmp_path / "large.c").write_text("\n".join(lines))
        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)
        assert graph.node_count > 0

    def test_empty_file(self, tmp_path: Path) -> None:
        """An empty .c file should not crash."""
        (tmp_path / "empty.c").write_text("")
        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        """Nonexistent directory should raise or return empty, not hang."""
        ext = TreeSitterExtractor()
        # os.walk on nonexistent path just returns nothing
        graph = ext.extract(tmp_path / "does_not_exist")
        assert isinstance(graph, GraphData)
        assert graph.node_count == 0

    def test_only_unsupported_extensions(self, tmp_path: Path) -> None:
        """Directory with only unsupported file types should return empty graph."""
        (tmp_path / "data.csv").write_text("a,b,c\n1,2,3")
        (tmp_path / "notes.txt").write_text("hello world")
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n")
        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)
        assert graph.node_count == 0

    def test_unicode_content(self, tmp_path: Path) -> None:
        """Source files with unicode content should not crash."""
        content = '// Comment with unicode: \u00e4\u00f6\u00fc \u00df \u2603 \u2764\nvoid func() { return; }\n'
        (tmp_path / "unicode.c").write_text(content, encoding="utf-8")
        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)
        assert graph.node_count > 0


class TestAnnotationErrors:
    """Test AnnotationExtractor handles bad input gracefully."""

    def test_empty_dir(self, tmp_path: Path) -> None:
        """Empty directory should return empty graph."""
        ext = AnnotationExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)
        assert graph.node_count == 0

    def test_file_without_annotations(self, tmp_path: Path) -> None:
        """A clean source file should produce no annotation nodes."""
        (tmp_path / "clean.c").write_text("void main() { return; }")
        ext = AnnotationExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)
        assert graph.node_count == 0

    def test_binary_file_skipped(self, tmp_path: Path) -> None:
        """Binary files with source extension should not crash."""
        (tmp_path / "binary.c").write_bytes(b"\x00\x01\x02" * 50)
        ext = AnnotationExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)


class TestDependencyErrors:
    """Test DependencyExtractor handles bad input gracefully."""

    def test_malformed_json(self, tmp_path: Path) -> None:
        """Malformed package.json should not crash."""
        (tmp_path / "package.json").write_text("{broken json")
        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)

    def test_empty_manifest(self, tmp_path: Path) -> None:
        """Empty manifest file should not crash."""
        (tmp_path / "Cargo.toml").write_text("")
        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)

    def test_empty_dir(self, tmp_path: Path) -> None:
        """Directory with no manifests should return empty graph."""
        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)
        assert graph.node_count == 0

    def test_package_json_no_deps(self, tmp_path: Path) -> None:
        """package.json without dependencies key should not crash."""
        (tmp_path / "package.json").write_text('{"name": "test", "version": "1.0.0"}')
        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)
        assert isinstance(graph, GraphData)


# ── GraphData error handling ─────────────────────────────────────────────────


class TestGraphDataErrors:
    """Test GraphData handles edge cases."""

    def test_duplicate_node_ids_dedup(self) -> None:
        """Adding duplicate node IDs followed by deduplicate should yield one node."""
        graph = GraphData()
        graph.add_node("func:a:foo:1", NodeLabel.FUNCTION, name="foo")
        graph.add_node("func:a:foo:1", NodeLabel.FUNCTION, name="foo_updated")
        assert graph.node_count == 2  # Before dedup, both exist in list
        graph.deduplicate()
        assert graph.node_count == 1
        # Later properties should overwrite earlier ones
        assert graph.nodes[0].properties["name"] == "foo_updated"

    def test_duplicate_edges_dedup(self) -> None:
        """Duplicate edges should be collapsed by deduplicate."""
        graph = GraphData()
        graph.add_node("func:a:foo:1", NodeLabel.FUNCTION, name="foo")
        graph.add_node("func:a:bar:2", NodeLabel.FUNCTION, name="bar")
        graph.add_edge("func:a:foo:1", "func:a:bar:2", EdgeType.CALLS)
        graph.add_edge("func:a:foo:1", "func:a:bar:2", EdgeType.CALLS)
        assert graph.edge_count == 2  # Before dedup
        graph.deduplicate()
        assert graph.edge_count == 1

    def test_edge_to_nonexistent_node(self) -> None:
        """Edge referencing nonexistent node should not crash."""
        graph = GraphData()
        graph.add_node("func:a:foo:1", NodeLabel.FUNCTION, name="foo")
        graph.add_edge("func:a:foo:1", "func:nonexistent:1", EdgeType.CALLS)
        # Should not crash, edge count should be 1
        assert graph.edge_count == 1

    def test_merge_empty_graphs(self) -> None:
        """Merging two empty graphs should work."""
        g1 = GraphData()
        g2 = GraphData()
        g1.merge(g2)
        assert g1.node_count == 0
        assert g1.edge_count == 0

    def test_merge_preserves_all_nodes(self) -> None:
        """Merging should combine nodes from both graphs."""
        g1 = GraphData()
        g1.add_node("func:a:foo:1", NodeLabel.FUNCTION, name="foo")
        g2 = GraphData()
        g2.add_node("func:b:bar:1", NodeLabel.FUNCTION, name="bar")
        g1.merge(g2)
        assert g1.node_count == 2

    def test_merge_preserves_warnings(self) -> None:
        """Merging should combine warnings from both graphs."""
        g1 = GraphData()
        g1.warnings.append("warn1")
        g2 = GraphData()
        g2.warnings.append("warn2")
        g1.merge(g2)
        assert len(g1.warnings) == 2

    def test_stats_on_empty_graph(self) -> None:
        """Stats on empty graph should return valid structure."""
        graph = GraphData()
        stats = graph.stats()
        assert "nodes" in stats
        assert "edges" in stats
        assert stats["nodes"] == {}
        assert stats["edges"] == {}

    def test_stats_counts_correct(self) -> None:
        """Stats should return accurate per-label and per-type counts."""
        graph = GraphData()
        graph.add_node("f1", NodeLabel.FUNCTION, name="f1")
        graph.add_node("f2", NodeLabel.FUNCTION, name="f2")
        graph.add_node("c1", NodeLabel.CLASS, name="C1")
        graph.add_edge("f1", "f2", EdgeType.CALLS)
        graph.add_edge("c1", "f1", EdgeType.CONTAINS)
        stats = graph.stats()
        assert stats["nodes"][NodeLabel.FUNCTION] == 2
        assert stats["nodes"][NodeLabel.CLASS] == 1
        assert stats["edges"][EdgeType.CALLS] == 1
        assert stats["edges"][EdgeType.CONTAINS] == 1

    def test_add_node_returns_node(self) -> None:
        """add_node should return the created Node object."""
        graph = GraphData()
        node = graph.add_node("func:test:1", NodeLabel.FUNCTION, name="test")
        assert node.id == "func:test:1"
        assert node.label == NodeLabel.FUNCTION
        assert node.properties["name"] == "test"

    def test_add_edge_returns_edge(self) -> None:
        """add_edge should return the created Edge object."""
        graph = GraphData()
        edge = graph.add_edge("a", "b", EdgeType.CALLS, weight=5)
        assert edge.source_id == "a"
        assert edge.target_id == "b"
        assert edge.type == EdgeType.CALLS
        assert edge.properties["weight"] == 5


# ── Manifest / scan errors ───────────────────────────────────────────────────


class TestManifestErrors:
    """Test manifest scan handles edge cases."""

    def test_scan_with_no_source_files(self, tmp_path: Path) -> None:
        """Directory with no source files should return empty dict."""
        (tmp_path / "readme.txt").write_text("hello")
        (tmp_path / "data.csv").write_text("a,b\n1,2")
        files = scan_current_files(tmp_path)
        assert len(files) == 0

    def test_scan_with_source_files(self, tmp_path: Path) -> None:
        """Directory with source files should return entries for each."""
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        (tmp_path / "lib.rs").write_text("fn main() {}")
        files = scan_current_files(tmp_path)
        assert len(files) == 2
        assert "main.c" in files
        assert "lib.rs" in files

    def test_scan_skips_build_dirs(self, tmp_path: Path) -> None:
        """Files inside SKIP_DIRS (build, node_modules) should be excluded."""
        build = tmp_path / "build"
        build.mkdir()
        (build / "output.c").write_text("int x;")
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        files = scan_current_files(tmp_path)
        assert len(files) == 1
        assert "main.c" in files

    def test_scan_empty_dir(self, tmp_path: Path) -> None:
        """Empty directory should return empty dict without error."""
        files = scan_current_files(tmp_path)
        assert files == {}


# ── Config validation ────────────────────────────────────────────────────────


class TestConfigErrors:
    """Test config validation edge cases."""

    def test_extract_config_with_unknown_language(self) -> None:
        """ExtractConfig with unknown language should not crash at creation."""
        config = ExtractConfig(repo_path=Path("/tmp/test"), languages=["klingon"])
        assert "klingon" in config.languages

    def test_extract_config_zero_workers(self) -> None:
        """workers=0 should mean auto-detect."""
        config = ExtractConfig(repo_path=Path("/tmp/test"), workers=0)
        assert config.workers == 0

    def test_extract_config_defaults(self) -> None:
        """Default config should have sensible values."""
        config = ExtractConfig(repo_path=Path("/tmp/test"))
        assert config.include_git is True
        assert config.include_deps is True
        assert config.max_file_size == 1_000_000
        assert len(config.languages) > 0

    def test_extract_config_custom_values(self) -> None:
        """Custom values should be stored correctly."""
        config = ExtractConfig(
            repo_path=Path("/tmp/project"),
            languages=["rust", "go"],
            workers=4,
            max_file_size=500_000,
            include_git=False,
        )
        assert config.languages == ["rust", "go"]
        assert config.workers == 4
        assert config.max_file_size == 500_000
        assert config.include_git is False
