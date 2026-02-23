"""Tests for the graph builder pipeline."""

import json
import subprocess
import textwrap
from pathlib import Path

import pytest

from archgraph.config import ExtractConfig
from archgraph.graph.builder import GraphBuilder
from archgraph.graph.schema import NodeLabel, EdgeType
from archgraph.manifest import load_manifest, delete_manifest


@pytest.fixture
def sample_c_project(tmp_path):
    """Create a small C project with git history for integration testing."""
    # Create source files
    (tmp_path / "main.c").write_text(textwrap.dedent("""\
        #include <stdio.h>
        #include <string.h>
        #include "parser.h"

        // TODO: add input validation
        int main(int argc, char *argv[]) {
            char buf[256];
            // HACK: temporary workaround
            if (argc > 1) {
                strcpy(buf, argv[1]);
                parse_data(buf);
            }
            return 0;
        }
    """))

    (tmp_path / "parser.h").write_text(textwrap.dedent("""\
        #ifndef PARSER_H
        #define PARSER_H

        struct ParseResult {
            int status;
            char *data;
        };

        struct ParseResult parse_data(const char *input);
        void free_result(struct ParseResult *result);

        #endif
    """))

    (tmp_path / "parser.c").write_text(textwrap.dedent("""\
        #include <stdlib.h>
        #include <string.h>
        #include "parser.h"

        struct ParseResult parse_data(const char *input) {
            struct ParseResult result;
            result.data = malloc(strlen(input) + 1);
            memcpy(result.data, input, strlen(input) + 1);
            result.status = 0;
            return result;
        }

        void free_result(struct ParseResult *result) {
            free(result->data);
            result->data = NULL;
        }
    """))

    # Create CMakeLists.txt
    (tmp_path / "CMakeLists.txt").write_text(textwrap.dedent("""\
        cmake_minimum_required(VERSION 3.14)
        project(parser_demo)
        find_package(OpenSSL REQUIRED)
        add_executable(demo main.c parser.c)
    """))

    # Initialize git repo
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "dev@test.com"],
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Developer"],
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], capture_output=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "Initial commit"],
        capture_output=True,
    )

    return tmp_path


def test_full_pipeline(sample_c_project):
    """Integration test: full extraction pipeline without Neo4j."""
    config = ExtractConfig(
        repo_path=sample_c_project,
        languages=["c"],
        include_git=True,
        include_deps=True,
        include_annotations=True,
        include_security_labels=True,
    )

    builder = GraphBuilder(config)
    graph = builder.build()

    # Should have files
    file_nodes = [n for n in graph.nodes if n.label == NodeLabel.FILE]
    file_paths = {n.properties["path"] for n in file_nodes}
    assert "main.c" in file_paths
    assert "parser.c" in file_paths
    assert "parser.h" in file_paths

    # Should have functions
    func_nodes = [n for n in graph.nodes if n.label == NodeLabel.FUNCTION]
    func_names = {n.properties.get("name") for n in func_nodes}
    assert "main" in func_names
    assert "parse_data" in func_names
    assert "free_result" in func_names

    # Should have struct
    struct_nodes = [n for n in graph.nodes if n.label == NodeLabel.STRUCT]
    struct_names = {n.properties.get("name") for n in struct_nodes}
    assert "ParseResult" in struct_names

    # Should have CALLS edges
    calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
    assert len(calls) > 0

    # Should have annotations (TODO and HACK)
    ann_nodes = [n for n in graph.nodes if n.label == NodeLabel.ANNOTATION]
    ann_types = {n.properties["type"] for n in ann_nodes}
    assert "TODO" in ann_types
    assert "HACK" in ann_types

    # Should have dependencies (OpenSSL from CMakeLists.txt)
    dep_nodes = [n for n in graph.nodes if n.label == NodeLabel.DEPENDENCY]
    dep_names = {n.properties["name"] for n in dep_nodes}
    assert "OpenSSL" in dep_names

    # Should have git history
    commit_nodes = [n for n in graph.nodes if n.label == NodeLabel.COMMIT]
    assert len(commit_nodes) >= 1

    # Security labels: strcpy should be labeled as dangerous sink
    dangerous_funcs = {
        n.properties["name"]
        for n in graph.nodes
        if n.label == NodeLabel.FUNCTION and n.properties.get("is_dangerous_sink")
    }
    assert "strcpy" in dangerous_funcs or "memcpy" in dangerous_funcs

    # malloc/free should be labeled as allocator
    alloc_funcs = {
        n.properties["name"]
        for n in graph.nodes
        if n.label == NodeLabel.FUNCTION and n.properties.get("is_allocator")
    }
    assert "malloc" in alloc_funcs or "free" in alloc_funcs

    # Stats should be non-empty
    stats = graph.stats()
    assert len(stats["nodes"]) > 0
    assert len(stats["edges"]) > 0


def test_pipeline_with_clang(sample_c_project):
    """Integration test: pipeline with clang deep analysis enabled."""
    try:
        import clang.cindex  # noqa: F401
    except ImportError:
        pytest.skip("libclang not installed")

    config = ExtractConfig(
        repo_path=sample_c_project,
        languages=["c"],
        include_git=False,
        include_deps=False,
        include_annotations=False,
        include_security_labels=True,
        include_clang=True,
    )

    builder = GraphBuilder(config)
    graph = builder.build()

    # Should have BasicBlock nodes from clang analysis
    bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
    assert len(bb_nodes) > 0, "Clang should produce BasicBlock nodes"

    # Should have BRANCHES_TO edges
    branches = [e for e in graph.edges if e.type == EdgeType.BRANCHES_TO]
    # main() has an if statement, should produce branches
    assert len(branches) >= 1

    # Should have CONTAINS edges for BasicBlocks
    bb_contains = [
        e for e in graph.edges
        if e.type == EdgeType.CONTAINS and e.target_id.startswith("bb:")
    ]
    assert len(bb_contains) > 0


def test_pipeline_with_deep(tmp_path):
    """Integration test: pipeline with tree-sitter deep analysis enabled."""
    (tmp_path / "lib.rs").write_text(textwrap.dedent("""\
        fn process(x: i32) -> i32 {
            let y = x + 1;
            if y > 0 {
                return y;
            }
            0
        }
    """))

    config = ExtractConfig(
        repo_path=tmp_path,
        languages=["rust"],
        include_git=False,
        include_deps=False,
        include_annotations=False,
        include_security_labels=False,
        include_deep=True,
    )

    builder = GraphBuilder(config)
    graph = builder.build()

    # Should have BasicBlock nodes from deep analysis
    bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
    assert len(bb_nodes) > 0, "Deep analysis should produce BasicBlock nodes"

    # Should have BRANCHES_TO edges (if statement)
    branches = [e for e in graph.edges if e.type == EdgeType.BRANCHES_TO]
    assert len(branches) >= 1

    # Should have CONTAINS edges for BasicBlocks
    bb_contains = [
        e for e in graph.edges
        if e.type == EdgeType.CONTAINS and e.target_id.startswith("bb:")
    ]
    assert len(bb_contains) > 0


def test_pipeline_without_git(tmp_path):
    """Test pipeline with git disabled."""
    (tmp_path / "test.c").write_text("int main() { return 0; }\n")

    config = ExtractConfig(
        repo_path=tmp_path,
        languages=["c"],
        include_git=False,
        include_deps=False,
        include_annotations=False,
        include_security_labels=False,
    )

    builder = GraphBuilder(config)
    graph = builder.build()

    # Should still have the file and function
    assert graph.node_count > 0
    file_nodes = [n for n in graph.nodes if n.label == NodeLabel.FILE]
    assert len(file_nodes) == 1


def test_pipeline_parallel(sample_c_project):
    """Parallel and sequential pipelines should produce equivalent results."""
    base_kwargs = dict(
        repo_path=sample_c_project,
        languages=["c"],
        include_git=True,
        include_deps=True,
        include_annotations=True,
        include_security_labels=True,
    )

    config_seq = ExtractConfig(**base_kwargs, workers=1)
    config_par = ExtractConfig(**base_kwargs, workers=4)

    graph_seq = GraphBuilder(config_seq).build()
    graph_par = GraphBuilder(config_par).build()

    seq_stats = graph_seq.stats()
    par_stats = graph_par.stats()

    # Same node labels should be present
    assert set(seq_stats["nodes"].keys()) == set(par_stats["nodes"].keys())
    # Same edge types should be present
    assert set(seq_stats["edges"].keys()) == set(par_stats["edges"].keys())
    # Same total counts
    assert graph_seq.node_count == graph_par.node_count
    assert graph_seq.edge_count == graph_par.edge_count


# ── Incremental Extraction Tests ─────────────────────────────────────────────


def test_incremental_no_manifest_fallback(sample_c_project):
    """Incremental with no prior manifest should fall back to full build and create manifest."""
    # Ensure no manifest exists
    delete_manifest(sample_c_project)
    assert load_manifest(sample_c_project) is None

    config = ExtractConfig(
        repo_path=sample_c_project,
        languages=["c"],
        include_git=True,
        include_deps=True,
        include_annotations=True,
        include_security_labels=True,
        incremental=True,
    )

    builder = GraphBuilder(config)
    graph = builder.build()

    # Should produce a full graph (non-empty)
    assert graph.node_count > 0
    assert graph.edge_count > 0

    # Should now have a manifest
    manifest = load_manifest(sample_c_project)
    assert manifest is not None
    assert len(manifest.files) > 0


def test_incremental_modified_file(sample_c_project):
    """After full build + modifying a file, incremental should only re-extract changed files."""
    # First: full build to create manifest
    config = ExtractConfig(
        repo_path=sample_c_project,
        languages=["c"],
        include_git=False,
        include_deps=False,
        include_annotations=False,
        include_security_labels=False,
        incremental=False,
    )
    full_graph = GraphBuilder(config).build()
    full_count = full_graph.node_count
    assert full_count > 0

    # Manifest should exist
    manifest = load_manifest(sample_c_project)
    assert manifest is not None
    old_file_count = len(manifest.files)

    # Modify one file
    (sample_c_project / "parser.c").write_text(
        'int new_func() { return 42; }\n', encoding="utf-8"
    )

    # Incremental build
    config_incr = ExtractConfig(
        repo_path=sample_c_project,
        languages=["c"],
        include_git=False,
        include_deps=False,
        include_annotations=False,
        include_security_labels=False,
        incremental=True,
    )
    incr_graph = GraphBuilder(config_incr).build()

    # Incremental graph should have nodes (at least the modified file)
    assert incr_graph.node_count > 0

    # Updated manifest should still have the same file count
    updated_manifest = load_manifest(sample_c_project)
    assert updated_manifest is not None
    assert len(updated_manifest.files) == old_file_count


def test_incremental_deleted_file(sample_c_project):
    """After full build + deleting a file, incremental should detect the deletion."""
    # First: full build
    config = ExtractConfig(
        repo_path=sample_c_project,
        languages=["c"],
        include_git=False,
        include_deps=False,
        include_annotations=False,
        include_security_labels=False,
        incremental=False,
    )
    GraphBuilder(config).build()

    manifest = load_manifest(sample_c_project)
    assert manifest is not None
    old_file_count = len(manifest.files)
    assert old_file_count >= 3  # main.c, parser.c, parser.h

    # Delete a file
    (sample_c_project / "parser.c").unlink()

    # Incremental build
    config_incr = ExtractConfig(
        repo_path=sample_c_project,
        languages=["c"],
        include_git=False,
        include_deps=False,
        include_annotations=False,
        include_security_labels=False,
        incremental=True,
    )
    incr_graph = GraphBuilder(config_incr).build()

    # Updated manifest should have one less file
    updated_manifest = load_manifest(sample_c_project)
    assert updated_manifest is not None
    assert len(updated_manifest.files) == old_file_count - 1
    assert "parser.c" not in updated_manifest.files

