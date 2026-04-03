"""Tests for SCIP-based call resolution."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from archgraph.graph.schema import GraphData, Node, NodeLabel, EdgeType


# ── Task 1: Proto Import ─────────────────────────────────────────────────────


class TestScipProto:
    def test_import_scip_pb2(self):
        from archgraph.extractors import scip_pb2
        idx = scip_pb2.Index()
        assert hasattr(idx, "documents")
        assert hasattr(idx, "metadata")

    def test_create_mock_index(self):
        from archgraph.extractors import scip_pb2
        idx = scip_pb2.Index()
        doc = idx.documents.add()
        doc.relative_path = "src/main.ts"
        occ = doc.occurrences.add()
        occ.symbol = "test_symbol"
        occ.symbol_roles = 1
        occ.range.extend([10, 0, 10, 5])
        assert len(idx.documents) == 1
        assert idx.documents[0].occurrences[0].symbol == "test_symbol"


# ── Helper ────────────────────────────────────────────────────────────────────

from archgraph.extractors import scip_pb2
from archgraph.extractors.scip_resolver import (
    ScipResolver, TypeScriptIndexer, parse_scip_index, _extract_name_from_symbol,
)


def _make_scip_index(documents: list[dict]) -> bytes:
    """Create a serialized SCIP index from a simple dict structure."""
    idx = scip_pb2.Index()
    for doc_dict in documents:
        doc = idx.documents.add()
        doc.relative_path = doc_dict["path"]
        for occ_dict in doc_dict.get("occurrences", []):
            occ = doc.occurrences.add()
            occ.symbol = occ_dict["symbol"]
            occ.symbol_roles = occ_dict.get("roles", 0)
            occ.range.extend(occ_dict.get("range", [0, 0, 0, 0]))
    return idx.SerializeToString()


# ── Task 2: TypeScriptIndexer ─────────────────────────────────────────────────


class TestTypeScriptIndexer:
    def test_install_no_npm(self):
        with patch("shutil.which", return_value=None):
            assert TypeScriptIndexer().install(Path("/fake")) is False

    def test_install_runs_npm(self):
        with patch("shutil.which", return_value="/usr/bin/npm"), \
             patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=1),  # version check fails
                MagicMock(returncode=0),  # npm install succeeds
                MagicMock(returncode=0),  # version check passes
            ]
            assert TypeScriptIndexer().install(Path("/fake")) is True
            install_call = mock_run.call_args_list[1]
            assert "@sourcegraph/scip-typescript" in " ".join(install_call[0][0])

    def test_index_returns_none_on_failure(self, tmp_path):
        (tmp_path / "tsconfig.json").write_text("{}")
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="error")):
            assert TypeScriptIndexer().index(tmp_path) is None

    def test_index_infers_tsconfig(self, tmp_path):
        (tmp_path / ".archgraph").mkdir()
        (tmp_path / ".archgraph" / "index.scip").write_bytes(b"fake")
        with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
            TypeScriptIndexer().index(tmp_path)
            assert "--infer-tsconfig" in mock_run.call_args[0][0]


# ── Task 3: SCIP Parsing ─────────────────────────────────────────────────────


class TestScipParsing:
    def test_definitions_extracted(self):
        data = _make_scip_index([{
            "path": "src/utils.ts",
            "occurrences": [
                {"symbol": "npm pkg `src/utils.ts`/add().", "roles": 1, "range": [5, 0, 5, 3]},
                {"symbol": "npm pkg `src/utils.ts`/subtract().", "roles": 1, "range": [10, 0, 10, 8]},
            ],
        }])
        sym_to_def, refs = parse_scip_index(data)
        assert len(sym_to_def) == 2
        assert sym_to_def["npm pkg `src/utils.ts`/add()."] == ("src/utils.ts", 5, "add")

    def test_references_collected(self):
        data = _make_scip_index([{
            "path": "src/app.ts",
            "occurrences": [
                {"symbol": "npm pkg `src/utils.ts`/add().", "roles": 0, "range": [3, 10, 3, 13]},
            ],
        }])
        _, refs = parse_scip_index(data)
        assert len(refs) == 1
        assert refs[0] == ("src/app.ts", 3, "npm pkg `src/utils.ts`/add().")

    def test_name_extraction(self):
        assert _extract_name_from_symbol("npm pkg `src/a.ts`/MyClass#method().") == "method"
        assert _extract_name_from_symbol("npm pkg `src/a.ts`/add().") == "add"
        assert _extract_name_from_symbol("local 42") == "local 42"


class TestCallerDetection:
    def test_inside_function(self):
        graph = GraphData()
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=1, line_end=10)
        graph.add_node("func:src/app.ts:helper:15", NodeLabel.FUNCTION,
                        name="helper", file="src/app.ts", line_start=15, line_end=20)
        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        assert resolver._find_enclosing_function("src/app.ts", 5).id == "func:src/app.ts:main:1"

    def test_second_function(self):
        graph = GraphData()
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=1, line_end=10)
        graph.add_node("func:src/app.ts:helper:15", NodeLabel.FUNCTION,
                        name="helper", file="src/app.ts", line_start=15, line_end=20)
        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        assert resolver._find_enclosing_function("src/app.ts", 17).id == "func:src/app.ts:helper:15"

    def test_outside_functions(self):
        graph = GraphData()
        graph.add_node("func:src/app.ts:main:5", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=5, line_end=10)
        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        assert resolver._find_enclosing_function("src/app.ts", 1) is None


# ── Task 4: Edge Generation + Cleanup ─────────────────────────────────────────


class TestEdgeGeneration:
    def test_scip_creates_resolved_edge(self):
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("file:src/utils.ts", NodeLabel.FILE, path="src/utils.ts")
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=1, line_end=10)
        graph.add_node("func:src/utils.ts:add:6", NodeLabel.FUNCTION,
                        name="add", file="src/utils.ts", line_start=6, line_end=8)
        graph.add_node("funcref:add", NodeLabel.FUNCTION, name="add")
        graph.add_edge("func:src/app.ts:main:1", "funcref:add", EdgeType.CALLS)

        scip_data = _make_scip_index([
            {"path": "src/utils.ts", "occurrences": [
                {"symbol": "pkg/add().", "roles": 1, "range": [5, 0, 5, 3]},
            ]},
            {"path": "src/app.ts", "occurrences": [
                {"symbol": "pkg/add().", "roles": 0, "range": [3, 10, 3, 13]},
            ]},
        ])

        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        count = resolver._apply_scip_data(scip_data, {"typescript"})
        assert count >= 1
        resolved = [e for e in graph.edges if e.properties.get("source") == "scip"]
        assert len(resolved) >= 1
        assert resolved[0].target_id == "func:src/utils.ts:add:6"

    def test_definitions_dont_create_edges(self):
        graph = GraphData()
        graph.add_node("func:src/a.ts:foo:1", NodeLabel.FUNCTION,
                        name="foo", file="src/a.ts", line_start=1, line_end=5)
        scip_data = _make_scip_index([{"path": "src/a.ts", "occurrences": [
            {"symbol": "pkg/foo().", "roles": 1, "range": [0, 0, 0, 3]},
        ]}])
        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        count = resolver._apply_scip_data(scip_data, {"typescript"})
        assert count == 0


class TestFuncrefCleanup:
    def test_funcref_removed_for_scip_languages(self):
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=1, line_end=10)
        graph.add_node("funcref:foo", NodeLabel.FUNCTION, name="foo")
        graph.add_edge("func:src/app.ts:main:1", "funcref:foo", EdgeType.CALLS)

        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        resolver._cleanup_funcref({"typescript", "javascript"})

        assert not any(n.id.startswith("funcref:") for n in graph.nodes)
        assert not any(e.target_id.startswith("funcref:") for e in graph.edges)

    def test_non_scip_funcref_preserved(self):
        graph = GraphData()
        graph.add_node("file:src/main.c", NodeLabel.FILE, path="src/main.c")
        graph.add_node("func:src/main.c:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/main.c", line_start=1, line_end=10)
        graph.add_node("funcref:printf", NodeLabel.FUNCTION, name="printf")
        graph.add_edge("func:src/main.c:main:1", "funcref:printf", EdgeType.CALLS)

        resolver = ScipResolver(graph, Path("/fake"), ["c"])
        resolver._cleanup_funcref(set())  # no SCIP languages

        assert any(n.id == "funcref:printf" for n in graph.nodes)


# ── Task 5: ClangScipIndexer ──────────────────────────────────────────────────


class TestClangScipIndexer:
    def test_registry_has_c_cpp(self):
        from archgraph.extractors.scip_resolver import INDEXER_REGISTRY, ClangScipIndexer
        assert "c" in INDEXER_REGISTRY
        assert "cpp" in INDEXER_REGISTRY
        assert INDEXER_REGISTRY["c"] is ClangScipIndexer
        assert INDEXER_REGISTRY["cpp"] is ClangScipIndexer

    def test_install_when_binary_exists(self):
        from archgraph.extractors.scip_resolver import ClangScipIndexer
        with patch.object(ClangScipIndexer, "_is_available", return_value=True):
            assert ClangScipIndexer().install(Path("/fake")) is True

    def test_install_no_binary_no_download(self):
        from archgraph.extractors.scip_resolver import ClangScipIndexer
        with patch.object(ClangScipIndexer, "_is_available", return_value=False), \
             patch.object(ClangScipIndexer, "_download_binary", return_value=False):
            assert ClangScipIndexer().install(Path("/fake")) is False

    def test_index_no_compdb(self, tmp_path):
        """No compile_commands.json should return None."""
        from archgraph.extractors.scip_resolver import ClangScipIndexer
        indexer = ClangScipIndexer()
        assert indexer.index(tmp_path) is None

    def test_index_with_compdb(self, tmp_path):
        """With compile_commands.json, should attempt scip-clang."""
        from archgraph.extractors.scip_resolver import ClangScipIndexer
        (tmp_path / "compile_commands.json").write_text("[]")
        (tmp_path / ".archgraph").mkdir()
        (tmp_path / ".archgraph" / "index.scip").write_bytes(b"fake")
        indexer = ClangScipIndexer()
        with patch.object(indexer, "_scip_clang_path", return_value="scip-clang"), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)):
            result = indexer.index(tmp_path)
            assert result is not None

    def test_cmake_generation_attempted(self, tmp_path):
        """Should try cmake if CMakeLists.txt exists but no compile_commands.json."""
        from archgraph.extractors.scip_resolver import ClangScipIndexer
        (tmp_path / "CMakeLists.txt").write_text("project(test)")
        indexer = ClangScipIndexer()
        with patch("shutil.which", return_value="/usr/bin/cmake"), \
             patch("subprocess.run", return_value=MagicMock(returncode=1)):
            # cmake fails, so index returns None
            result = indexer.index(tmp_path)
            assert result is None


class TestFallback:
    def test_c_uses_heuristic(self):
        graph = GraphData()
        graph.add_node("func:src/a.c:helper:1", NodeLabel.FUNCTION,
                        name="helper", file="src/a.c", line_start=1, line_end=3)
        graph.add_node("func:src/a.c:main:5", NodeLabel.FUNCTION,
                        name="main", file="src/a.c", line_start=5, line_end=10)
        graph.add_node("funcref:helper", NodeLabel.FUNCTION, name="helper")
        graph.add_edge("func:src/a.c:main:5", "funcref:helper", EdgeType.CALLS)

        resolver = ScipResolver(graph, Path("/fake"), ["c"])
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert calls[0].target_id == "func:src/a.c:helper:1"
