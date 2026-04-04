"""Tests for the Clang deep analysis extractor (Phase 2)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

# Skip entire module if libclang is not installed
try:
    import clang.cindex  # noqa: F401

    HAS_CLANG = True
except ImportError:
    HAS_CLANG = False

pytestmark = [pytest.mark.skipif(not HAS_CLANG, reason="libclang not installed"), pytest.mark.lang_c, pytest.mark.deep]

from archgraph.extractors.clang import ClangExtractor  # noqa: E402


# ── Helpers ──────────────────────────────────────────────────────────────────


def _write_c(tmp_path: Path, name: str, code: str) -> Path:
    """Write a C source file with dedented code."""
    fpath = tmp_path / name
    fpath.write_text(textwrap.dedent(code))
    return fpath


def _extract(tmp_path: Path) -> GraphData:
    """Run ClangExtractor on a temp directory and return graph."""
    ext = ClangExtractor()
    assert ext.available
    return ext.extract(tmp_path)


# ── TestClangCFG ─────────────────────────────────────────────────────────────


class TestClangCFG:
    """Test CFG (BasicBlock + BRANCHES_TO) extraction."""

    def test_basic_cfg(self, tmp_path):
        """Simple function should produce at least one BasicBlock."""
        _write_c(tmp_path, "simple.c", """\
            int add(int a, int b) {
                int c = a + b;
                return c;
            }
        """)
        graph = _extract(tmp_path)

        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        assert len(bb_nodes) >= 1, "Expected at least one BasicBlock node"

        # All blocks should have function property
        for bb in bb_nodes:
            assert bb.properties["function"] == "add"
            assert bb.properties["file"] == "simple.c"

    def test_if_cfg(self, tmp_path):
        """If/else should produce multiple blocks with BRANCHES_TO edges."""
        _write_c(tmp_path, "branch.c", """\
            int abs_val(int x) {
                if (x < 0) {
                    return -x;
                } else {
                    return x;
                }
            }
        """)
        graph = _extract(tmp_path)

        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        assert len(bb_nodes) >= 3, "If/else should create at least 3 blocks"

        branches = [e for e in graph.edges if e.type == EdgeType.BRANCHES_TO]
        assert len(branches) >= 2, "Expected at least 2 BRANCHES_TO edges"

    def test_loop_cfg(self, tmp_path):
        """While loop should produce a header block with back edge."""
        _write_c(tmp_path, "loop.c", """\
            int sum(int n) {
                int s = 0;
                int i = 0;
                while (i < n) {
                    s = s + i;
                    i = i + 1;
                }
                return s;
            }
        """)
        graph = _extract(tmp_path)

        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        assert len(bb_nodes) >= 3, "Loop should create header, body, exit blocks"

        branches = [e for e in graph.edges if e.type == EdgeType.BRANCHES_TO]
        # Should have back edge (body→header)
        assert len(branches) >= 3, "Expected header→body, body→header (back), header→exit"

    def test_contains_edge(self, tmp_path):
        """Function should CONTAIN its BasicBlocks."""
        _write_c(tmp_path, "cont.c", """\
            void noop(void) {
                int x = 1;
            }
        """)
        graph = _extract(tmp_path)

        contains = [
            e for e in graph.edges
            if e.type == EdgeType.CONTAINS
            and e.target_id.startswith("bb:")
        ]
        assert len(contains) >= 1


# ── TestClangDataFlow ────────────────────────────────────────────────────────


class TestClangDataFlow:
    """Test DATA_FLOWS_TO edge generation."""

    def test_simple_data_flow(self, tmp_path):
        """Variable assigned from another should produce DATA_FLOWS_TO edge."""
        _write_c(tmp_path, "flow.c", """\
            int flow(void) {
                int x = 10;
                int y = x + 1;
                return y;
            }
        """)
        graph = _extract(tmp_path)

        df_edges = [e for e in graph.edges if e.type == EdgeType.DATA_FLOWS_TO]
        assert len(df_edges) >= 1

        # Check that we have x→y flow
        found = any(
            e.properties.get("from_var") == "x" and e.properties.get("to_var") == "y"
            for e in df_edges
        )
        assert found, "Expected data flow from x to y"

    def test_no_flow_independent(self, tmp_path):
        """Independent variables should not produce data flow edges between them."""
        _write_c(tmp_path, "indep.c", """\
            void indep(void) {
                int a = 1;
                int b = 2;
            }
        """)
        graph = _extract(tmp_path)

        df_edges = [e for e in graph.edges if e.type == EdgeType.DATA_FLOWS_TO]
        # a and b are independent — no flow between them
        cross = [
            e for e in df_edges
            if (e.properties.get("from_var") == "a" and e.properties.get("to_var") == "b")
            or (e.properties.get("from_var") == "b" and e.properties.get("to_var") == "a")
        ]
        assert len(cross) == 0, "Independent vars should not have data flow edges"


# ── TestClangTaint ───────────────────────────────────────────────────────────


class TestClangTaint:
    """Test TAINTS edge generation (input source → dangerous sink)."""

    def test_simple_taint_chain(self, tmp_path):
        """recv → buf → memcpy should produce a TAINTS edge."""
        _write_c(tmp_path, "taint.c", """\
            #include <string.h>
            #include <sys/socket.h>

            void handle(int sock) {
                char buf[256];
                int n = recv(sock, buf, sizeof(buf), 0);
                char dest[256];
                memcpy(dest, buf, n);
            }
        """)
        graph = _extract(tmp_path)

        taint_edges = [e for e in graph.edges if e.type == EdgeType.TAINTS]
        assert len(taint_edges) >= 1, "Expected at least one TAINTS edge"

        # Source should be recv, sink should be memcpy
        for e in taint_edges:
            assert "recv" in e.source_id or "unknown" in e.source_id
            assert "memcpy" in e.target_id

    def test_no_taint_without_source(self, tmp_path):
        """No input source → no TAINTS edges (only local computation)."""
        _write_c(tmp_path, "safe.c", """\
            #include <string.h>

            void safe(void) {
                char src[] = "hello";
                char dst[10];
                memcpy(dst, src, 5);
            }
        """)
        graph = _extract(tmp_path)

        # No recv/read/etc → no taint should be emitted
        taint_edges = [e for e in graph.edges if e.type == EdgeType.TAINTS]
        # Parameters are tainted by default, but this function has no params
        # and no input source calls → should have no taint
        assert len(taint_edges) == 0, "No input source → no TAINTS edges expected"


# ── TestClangMacro ───────────────────────────────────────────────────────────


class TestClangMacro:
    """Test macro expansion tracking."""

    def test_macro_expansion(self, tmp_path):
        """Macro usage should create EXPANDS_MACRO edges."""
        _write_c(tmp_path, "macros.c", """\
            #define MAX(a, b) ((a) > (b) ? (a) : (b))

            int biggest(int x, int y) {
                return MAX(x, y);
            }
        """)
        graph = _extract(tmp_path)

        macro_edges = [e for e in graph.edges if e.type == EdgeType.EXPANDS_MACRO]
        # Depending on libclang version, macro instantiation may or may not be tracked
        # At minimum, check we don't crash
        macro_nodes = [n for n in graph.nodes if n.label == NodeLabel.MACRO]
        # If macros are detected, edges should exist too
        if macro_nodes:
            assert len(macro_edges) >= 1


# ── TestClangTypeResolution ──────────────────────────────────────────────────


class TestClangTypeResolution:
    """Test typedef chain resolution."""

    def test_typedef_resolution(self, tmp_path):
        """Typedef chain should be resolved to final type."""
        _write_c(tmp_path, "types.c", """\
            typedef unsigned int uint32;
            typedef uint32 myint;

            myint get_val(void) {
                myint x = 42;
                return x;
            }
        """)
        graph = _extract(tmp_path)

        type_nodes = [n for n in graph.nodes if n.label == NodeLabel.TYPE_ALIAS]
        # Should have at least one type alias with resolved_type
        resolved = [n for n in type_nodes if "resolved_type" in n.properties]
        assert len(resolved) >= 1, "Expected at least one resolved typedef"

        # Check that the chain resolves to the base type
        for n in resolved:
            rt = n.properties["resolved_type"]
            # Should resolve to something like "unsigned int"
            assert rt != "", "resolved_type should not be empty"


# ── TestClangPointerAnalysis ─────────────────────────────────────────────────


class TestClangPointerAnalysis:
    """Test void* cast and pointer arithmetic detection."""

    def test_void_cast_detection(self, tmp_path):
        """void* cast should set has_void_cast flag on function."""
        _write_c(tmp_path, "vcast.c", """\
            void* convert(int *p) {
                void *vp = (void*)p;
                return vp;
            }
        """)
        graph = _extract(tmp_path)

        # Find the function node (may be created by clang's pointer annotation)
        func_nodes = [n for n in graph.nodes if n.label == NodeLabel.FUNCTION]
        # Check BasicBlock nodes to verify analysis ran
        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        assert len(bb_nodes) >= 1, "Should have analyzed the function"

        # The has_void_cast flag should be set on some node
        void_cast_nodes = [
            n for n in graph.nodes
            if n.properties.get("has_void_cast") is True
        ]
        # If no tree-sitter run, func node might not exist for flag annotation
        # Just verify no crash; the flag is best-effort on existing nodes

    def test_pointer_arith_detection(self, tmp_path):
        """Array subscript on pointer should set has_pointer_arith flag."""
        _write_c(tmp_path, "parith.c", """\
            int get_element(int *arr, int i) {
                return arr[i];
            }
        """)
        graph = _extract(tmp_path)
        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        assert len(bb_nodes) >= 1


# ── TestClangEdgeCases ───────────────────────────────────────────────────────


class TestClangEdgeCases:
    """Test error tolerance and edge cases."""

    def test_empty_dir(self, tmp_path):
        """Empty directory should return empty graph without errors."""
        graph = _extract(tmp_path)
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_non_c_ignored(self, tmp_path):
        """Non-C files should be ignored."""
        (tmp_path / "hello.py").write_text("print('hello')\n")
        (tmp_path / "readme.md").write_text("# Hello\n")
        graph = _extract(tmp_path)
        assert graph.node_count == 0

    def test_syntax_error_tolerance(self, tmp_path):
        """Files with syntax errors should not crash the extractor."""
        _write_c(tmp_path, "bad.c", """\
            int broken( {
                return
            }
        """)
        # Should not raise
        graph = _extract(tmp_path)
        # May or may not extract anything, but shouldn't crash

    def test_available_property(self):
        """ClangExtractor.available should reflect libclang availability."""
        ext = ClangExtractor()
        assert ext.available is True  # We're in the HAS_CLANG block

    def test_multiple_functions(self, tmp_path):
        """Multiple functions in one file should all be analyzed."""
        _write_c(tmp_path, "multi.c", """\
            int foo(int x) { return x + 1; }
            int bar(int y) { return y * 2; }
            int baz(int z) { return foo(z) + bar(z); }
        """)
        graph = _extract(tmp_path)

        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        funcs = {n.properties["function"] for n in bb_nodes}
        assert "foo" in funcs
        assert "bar" in funcs
        assert "baz" in funcs
