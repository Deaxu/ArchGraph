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


# ── Class Shell Tests ─────────────────────────────────────────────────────────


@pytest.fixture
def tmp_java_project(tmp_path):
    """Java file with a class containing methods."""
    src = tmp_path / "App.java"
    src.write_text(textwrap.dedent("""\
        public class App {
            private int count;

            public App(int initial) {
                this.count = initial;
            }

            public int getCount() {
                return this.count;
            }

            public void increment() {
                this.count++;
            }
        }
    """))
    return tmp_path


class TestClassShell:
    """Test class shell extraction - method bodies replaced with { ... }."""

    def test_java_class_shell(self, tmp_java_project):
        ext = TreeSitterExtractor(languages=["java"], include_body=True)
        graph = ext.extract(tmp_java_project)

        for node in graph.nodes:
            if node.label == NodeLabel.CLASS and node.properties.get("name") == "App":
                body = node.properties.get("body", "")
                # Should contain class header and field
                assert "class App" in body
                assert "private int count" in body
                # Method signatures should be present
                assert "public App(int initial)" in body
                assert "public int getCount()" in body
                assert "public void increment()" in body
                # Method bodies should be replaced with ...
                assert "this.count = initial" not in body
                assert "return this.count" not in body
                assert "this.count++" not in body
                assert "..." in body
                return
        pytest.fail("Class 'App' not found")

    def test_class_no_body_when_disabled(self, tmp_java_project):
        ext = TreeSitterExtractor(languages=["java"], include_body=False)
        graph = ext.extract(tmp_java_project)

        for node in graph.nodes:
            if node.label == NodeLabel.CLASS:
                assert "body" not in node.properties


# ── Struct/Interface/Enum Body Tests ──────────────────────────────────────────


@pytest.fixture
def tmp_rust_with_types(tmp_path):
    """Rust file with struct, trait, and enum."""
    src = tmp_path / "types.rs"
    src.write_text(textwrap.dedent("""\
        pub struct Point {
            pub x: f64,
            pub y: f64,
        }

        pub trait Drawable {
            fn draw(&self);
            fn area(&self) -> f64;
        }

        pub enum Shape {
            Circle(f64),
            Rectangle(f64, f64),
        }
    """))
    return tmp_path


class TestStructInterfaceEnumBody:
    """Test body extraction for Struct, Interface, Enum nodes."""

    def test_rust_struct_body(self, tmp_rust_with_types):
        ext = TreeSitterExtractor(languages=["rust"], include_body=True)
        graph = ext.extract(tmp_rust_with_types)

        for node in graph.nodes:
            if node.label == NodeLabel.STRUCT and node.properties.get("name") == "Point":
                body = node.properties.get("body", "")
                assert "pub struct Point" in body
                assert "pub x: f64" in body
                assert "pub y: f64" in body
                return
        pytest.fail("Struct 'Point' not found")

    def test_rust_trait_body(self, tmp_rust_with_types):
        ext = TreeSitterExtractor(languages=["rust"], include_body=True)
        graph = ext.extract(tmp_rust_with_types)

        for node in graph.nodes:
            if node.label == NodeLabel.INTERFACE and node.properties.get("name") == "Drawable":
                body = node.properties.get("body", "")
                assert "trait Drawable" in body
                assert "fn draw" in body
                assert "fn area" in body
                return
        pytest.fail("Interface 'Drawable' not found")

    def test_rust_enum_body(self, tmp_rust_with_types):
        ext = TreeSitterExtractor(languages=["rust"], include_body=True)
        graph = ext.extract(tmp_rust_with_types)

        for node in graph.nodes:
            if node.label == NodeLabel.ENUM and node.properties.get("name") == "Shape":
                body = node.properties.get("body", "")
                assert "enum Shape" in body
                assert "Circle" in body
                assert "Rectangle" in body
                return
        pytest.fail("Enum 'Shape' not found")


# ── Truncation Tests ──────────────────────────────────────────────────────────


class TestBodyTruncation:
    """Test body truncation when exceeding max_body_size."""

    def test_truncation_with_small_limit(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=True, max_body_size=30)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "add":
                body = node.properties.get("body", "")
                assert node.properties.get("body_truncated") is True
                assert "truncated:" in body
                return
        pytest.fail("Function 'add' not found")

    def test_no_truncation_within_limit(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=True, max_body_size=51_200)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "add":
                assert node.properties.get("body_truncated") is None
                return
        pytest.fail("Function 'add' not found")
