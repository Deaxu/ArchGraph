"""Tests for code body extraction feature."""

import textwrap
from pathlib import Path

import pytest

from archgraph.config import ExtractConfig
from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import NodeLabel


class TestBodyConfig:
    """Test include_body and max_body_size config fields."""

    def test_include_body_default_true(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"))
        assert config.include_body is True

    def test_max_body_size_default(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"))
        assert config.max_body_size == 51_200

    def test_include_body_override(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"), include_body=False)
        assert config.include_body is False

    def test_max_body_size_override(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"), max_body_size=10_000)
        assert config.max_body_size == 10_000


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_c_with_functions(tmp_path):
    """C file with functions of varying complexity."""
    src = tmp_path / "main.c"
    src.write_text(textwrap.dedent("""\
        int add(int a, int b) {
            return a + b;
        }

        void empty_func(void) {
        }
    """))
    return tmp_path


def _ts_lang_available(lang: str) -> bool:
    """Check if a tree-sitter language grammar is installed."""
    try:
        ext = TreeSitterExtractor(languages=[lang])
        return lang in ext._parsers
    except Exception:
        return False


# ── Function Body Tests ───────────────────────────────────────────────────────


class TestFunctionBody:
    """Test function body extraction."""

    def test_c_function_body(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=True)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "add":
                assert "body" in node.properties
                assert "int add(int a, int b)" in node.properties["body"]
                assert "return a + b;" in node.properties["body"]
                assert node.properties.get("body_lines", 0) > 0
                return
        pytest.fail("Function 'add' not found")

    def test_empty_function_body(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=True)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "empty_func":
                assert "body" in node.properties
                assert "void empty_func(void)" in node.properties["body"]
                assert node.properties.get("body_lines", 0) >= 1
                return
        pytest.fail("Function 'empty_func' not found")

    def test_no_body_when_disabled(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and not node.id.startswith("funcref:"):
                assert "body" not in node.properties
