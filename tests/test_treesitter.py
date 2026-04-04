"""Tests for the tree-sitter extractor."""

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import NodeLabel, EdgeType


@pytest.fixture
def tmp_c_project(tmp_path):
    """Create a minimal C project for testing."""
    src = tmp_path / "main.c"
    src.write_text(textwrap.dedent("""\
        #include <stdio.h>
        #include "util.h"

        struct Point {
            int x;
            int y;
        };

        typedef unsigned int uint;

        #define MAX_SIZE 1024

        int add(int a, int b) {
            return a + b;
        }

        static void helper(void) {
            printf("hello");
        }

        int main(int argc, char *argv[]) {
            int result = add(1, 2);
            helper();
            memcpy(NULL, NULL, 0);
            return 0;
        }
    """))

    util = tmp_path / "util.h"
    util.write_text(textwrap.dedent("""\
        #ifndef UTIL_H
        #define UTIL_H

        void do_something(void);

        #endif
    """))

    return tmp_path


@pytest.fixture
def tmp_rust_project(tmp_path):
    """Create a minimal Rust project for testing."""
    src = tmp_path / "lib.rs"
    src.write_text(textwrap.dedent("""\
        use std::io::Read;

        pub struct Config {
            pub name: String,
            pub value: i32,
        }

        pub trait Processor {
            fn process(&self, data: &[u8]) -> Vec<u8>;
        }

        impl Processor for Config {
            fn process(&self, data: &[u8]) -> Vec<u8> {
                data.to_vec()
            }
        }

        pub fn parse_input(input: &str) -> Config {
            Config {
                name: input.to_string(),
                value: 42,
            }
        }

        fn internal_helper() {
            println!("helper");
        }
    """))
    return tmp_path


def _has_node(graph, label, **props):
    """Check if graph has a node with given label and properties."""
    for node in graph.nodes:
        if node.label != label:
            continue
        if all(node.properties.get(k) == v for k, v in props.items()):
            return True
    return False


def _has_edge(graph, edge_type, source_substr=None, target_substr=None):
    """Check if graph has an edge of given type, optionally matching source/target substrings."""
    for edge in graph.edges:
        if edge.type != edge_type:
            continue
        if source_substr and source_substr not in edge.source_id:
            continue
        if target_substr and target_substr not in edge.target_id:
            continue
        return True
    return False


class TestTreeSitterC:
    """Test C language extraction."""

    pytestmark = pytest.mark.lang_c

    def test_extract_functions(self, tmp_c_project):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)

        # Should find add, helper, main
        func_names = {
            n.properties["name"]
            for n in graph.nodes
            if n.label == NodeLabel.FUNCTION
        }
        assert "add" in func_names
        assert "helper" in func_names
        assert "main" in func_names

    def test_extract_struct(self, tmp_c_project):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)

        assert _has_node(graph, NodeLabel.STRUCT, name="Point")

    def test_extract_macro(self, tmp_c_project):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)

        assert _has_node(graph, NodeLabel.MACRO, name="MAX_SIZE")

    def test_extract_includes(self, tmp_c_project):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)

        # Should have IMPORTS edges for stdio.h and util.h
        assert _has_edge(graph, EdgeType.IMPORTS, target_substr="stdio.h")
        assert _has_edge(graph, EdgeType.IMPORTS, target_substr="util.h")

    def test_extract_calls(self, tmp_c_project):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)

        # main calls add, helper, memcpy
        assert _has_edge(graph, EdgeType.CALLS, source_substr="main", target_substr="add")
        assert _has_edge(graph, EdgeType.CALLS, source_substr="main", target_substr="helper")
        assert _has_edge(graph, EdgeType.CALLS, source_substr="main", target_substr="memcpy")

    def test_export_detection(self, tmp_c_project):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)

        for node in graph.nodes:
            if node.label != NodeLabel.FUNCTION:
                continue
            # Skip unresolved call references (funcref:*), they don't have is_exported
            if node.id.startswith("funcref:"):
                continue
            if node.properties.get("name") == "helper":
                # static function should not be exported
                assert node.properties.get("is_exported") is False
            if node.properties.get("name") == "main":
                assert node.properties.get("is_exported") is True

    def test_file_node(self, tmp_c_project):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)

        assert _has_node(graph, NodeLabel.FILE, path="main.c", language="c")
        assert _has_node(graph, NodeLabel.FILE, path="util.h", language="c")

    def test_contains_edges(self, tmp_c_project):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)

        # File should contain functions
        assert _has_edge(graph, EdgeType.CONTAINS, source_substr="file:main.c")


class TestTreeSitterRust:
    """Test Rust language extraction."""

    pytestmark = pytest.mark.lang_rust

    def test_extract_functions(self, tmp_rust_project):
        ext = TreeSitterExtractor(languages=["rust"])
        graph = ext.extract(tmp_rust_project)

        func_names = {
            n.properties["name"]
            for n in graph.nodes
            if n.label == NodeLabel.FUNCTION
        }
        assert "parse_input" in func_names
        assert "internal_helper" in func_names

    def test_extract_struct(self, tmp_rust_project):
        ext = TreeSitterExtractor(languages=["rust"])
        graph = ext.extract(tmp_rust_project)

        assert _has_node(graph, NodeLabel.STRUCT, name="Config")

    def test_extract_trait(self, tmp_rust_project):
        ext = TreeSitterExtractor(languages=["rust"])
        graph = ext.extract(tmp_rust_project)

        assert _has_node(graph, NodeLabel.INTERFACE, name="Processor")

    def test_extract_use(self, tmp_rust_project):
        ext = TreeSitterExtractor(languages=["rust"])
        graph = ext.extract(tmp_rust_project)

        assert _has_edge(graph, EdgeType.IMPORTS, target_substr="std::io::Read")

    def test_export_detection_rust(self, tmp_rust_project):
        ext = TreeSitterExtractor(languages=["rust"])
        graph = ext.extract(tmp_rust_project)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "parse_input":
                assert node.properties.get("is_exported") is True
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "internal_helper":
                assert node.properties.get("is_exported") is False


class TestTreeSitterEmpty:
    """Test edge cases."""

    pytestmark = pytest.mark.core

    def test_empty_directory(self, tmp_path):
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_path)
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_unsupported_language(self, tmp_path):
        # Create a file with unsupported extension
        (tmp_path / "test.xyz").write_text("hello")
        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_path)
        assert graph.node_count == 0
