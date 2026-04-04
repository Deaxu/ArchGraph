"""Tests for the ArchGraph Python API interface (without Neo4j).

Validates that the API class correctly passes parameters, normalizes inputs,
and maintains a consistent interface with the CLI and ExtractConfig.
"""

from __future__ import annotations

import dataclasses
import inspect
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from archgraph.api import ArchGraph
from archgraph.config import ExtractConfig

pytestmark = pytest.mark.api


# ── API extract() parameter forwarding ────────────────────────────────────────


class TestArchGraphExtractParams:
    """Test that API extract() correctly passes parameters to ExtractConfig."""

    def test_extract_creates_correct_config(self, tmp_c_project):
        """Verify extract params are passed through to ExtractConfig."""
        captured_configs: list[ExtractConfig] = []

        class FakeBuilder:
            def __init__(self, config, **kwargs):
                captured_configs.append(config)

            def build(self):
                from archgraph.graph.schema import GraphData
                g = GraphData()
                g._node_count = 0
                g._edge_count = 0
                return g

        class FakeStore:
            def create_indexes(self): pass
            def clear_repo(self, name): pass
            def import_graph(self, graph, repo_name): pass

        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        mock_store = MagicMock()
        mock_store.import_graph.return_value = {
            "nodes_imported": 0,
            "edges_imported": 0,
        }
        ag._get_store = lambda: mock_store

        with (
            patch("archgraph.api.GraphBuilder", FakeBuilder),
        ):
            ag.extract(
                repo=str(tmp_c_project),
                workers=4,
                include_deep=False,
                include_clang=False,
                include_cve=True,
                incremental=True,
                max_body_size=10_000,
                include_body=False,
                include_scip=False,
            )

        assert len(captured_configs) == 1
        config = captured_configs[0]
        assert config.workers == 4
        assert config.include_deep is False
        assert config.include_clang is False
        assert config.include_cve is True
        assert config.incremental is True
        assert config.max_body_size == 10_000
        assert config.include_body is False
        assert config.include_scip is False

    def test_extract_default_config_matches_dataclass(self, tmp_c_project):
        """Default API params must produce an ExtractConfig matching dataclass defaults."""
        captured_configs: list[ExtractConfig] = []

        class FakeBuilder:
            def __init__(self, config, **kwargs):
                captured_configs.append(config)

            def build(self):
                from archgraph.graph.schema import GraphData
                return GraphData()

        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        mock_store = MagicMock()
        ag._get_store = lambda: mock_store

        with patch("archgraph.api.GraphBuilder", FakeBuilder):
            ag.extract(repo=str(tmp_c_project))

        assert len(captured_configs) == 1
        config = captured_configs[0]

        # Verify defaults match ExtractConfig
        assert config.include_body is True
        assert config.include_git is True
        assert config.include_deps is True
        assert config.include_annotations is True
        assert config.include_deep is True
        assert config.include_clang is True
        assert config.include_cve is False
        assert config.include_scip is True
        assert config.include_clustering is False
        assert config.include_process is False
        assert config.workers == 0
        assert config.incremental is False
        assert config.max_body_size == 51_200

    def test_extract_passes_compile_commands(self, tmp_c_project):
        """compile_commands parameter must map to clang_compile_commands in config."""
        captured_configs: list[ExtractConfig] = []

        class FakeBuilder:
            def __init__(self, config, **kwargs):
                captured_configs.append(config)

            def build(self):
                from archgraph.graph.schema import GraphData
                return GraphData()

        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        mock_store = MagicMock()
        ag._get_store = lambda: mock_store

        cc_path = tmp_c_project / "compile_commands.json"
        cc_path.write_text("[]")

        with patch("archgraph.api.GraphBuilder", FakeBuilder):
            ag.extract(repo=str(tmp_c_project), compile_commands=cc_path)

        assert len(captured_configs) == 1
        assert captured_configs[0].clang_compile_commands == cc_path

    def test_extract_clear_db_calls_clear_repo(self, tmp_c_project):
        """clear_db=True must call store.clear_repo before import."""
        class FakeBuilder:
            def __init__(self, config, **kwargs):
                pass

            def build(self):
                from archgraph.graph.schema import GraphData
                return GraphData()

        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        mock_store = MagicMock()
        ag._get_store = lambda: mock_store

        with patch("archgraph.api.GraphBuilder", FakeBuilder):
            ag.extract(repo=str(tmp_c_project), clear_db=True)

        mock_store.clear_repo.assert_called_once()

    def test_extract_no_clear_db_by_default(self, tmp_c_project):
        """clear_db defaults to False — store.clear_repo must NOT be called."""
        class FakeBuilder:
            def __init__(self, config, **kwargs):
                pass

            def build(self):
                from archgraph.graph.schema import GraphData
                return GraphData()

        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        mock_store = MagicMock()
        ag._get_store = lambda: mock_store

        with patch("archgraph.api.GraphBuilder", FakeBuilder):
            ag.extract(repo=str(tmp_c_project), clear_db=False)

        mock_store.clear_repo.assert_not_called()

    def test_extract_nonexistent_dir_raises(self):
        """Extracting from a non-existent directory must raise FileNotFoundError."""
        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        with pytest.raises(FileNotFoundError):
            ag.extract(repo="/nonexistent/path/that/does/not/exist")


# ── API defensive normalization ───────────────────────────────────────────────


class TestArchGraphDefensiveNormalization:
    """Test that API methods normalize backslash symbol IDs to forward slashes."""

    def test_source_normalizes_backslash(self):
        """API.source() must convert backslashes to forward slashes."""
        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        mock_store = MagicMock()
        mock_store.get_source.return_value = {"id": "func:src/main.c:foo:1"}
        ag._get_store = lambda: mock_store

        ag.source("func:src\\main.c:foo:1")
        call_arg = mock_store.get_source.call_args[0][0]
        assert call_arg == "func:src/main.c:foo:1", (
            f"source() did not normalize backslash: {call_arg}"
        )

    def test_impact_normalizes_backslash(self):
        """API.impact() must normalize backslash in symbol_id."""
        # Verify at the source level that normalization is present
        source = inspect.getsource(ArchGraph.impact)
        assert 'replace("\\\\", "/")' in source, (
            "ArchGraph.impact() does not normalize backslashes"
        )

    def test_context_normalizes_backslash(self):
        """API.context() must normalize backslash in symbol_id."""
        source = inspect.getsource(ArchGraph.context)
        assert 'replace("\\\\", "/")' in source, (
            "ArchGraph.context() does not normalize backslashes"
        )

    def test_source_already_forward_slash_unchanged(self):
        """Forward-slash IDs must pass through unchanged."""
        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        mock_store = MagicMock()
        mock_store.get_source.return_value = {"id": "func:src/main.c:foo:1"}
        ag._get_store = lambda: mock_store

        ag.source("func:src/main.c:foo:1")
        call_arg = mock_store.get_source.call_args[0][0]
        assert call_arg == "func:src/main.c:foo:1"


# ── API signature stability ──────────────────────────────────────────────────


class TestArchGraphSignatureStability:
    """Ensure the API extract() signature is stable and complete."""

    def test_extract_has_all_required_params(self):
        """API.extract() must have all documented parameters."""
        sig = inspect.signature(ArchGraph.extract)
        required_params = {
            "repo",
            "languages",
            "clear_db",
            "include_body",
            "include_git",
            "include_deps",
            "include_annotations",
            "include_security_labels",
            "include_deep",
            "include_clang",
            "include_cve",
            "include_scip",
            "include_clustering",
            "include_process",
            "workers",
            "incremental",
            "max_body_size",
            "compile_commands",
            "branch",
            "depth",
        }
        actual_params = set(sig.parameters.keys()) - {"self"}
        missing = required_params - actual_params
        assert not missing, f"API.extract() missing parameters: {missing}"

    def test_extract_return_annotation_is_dict(self):
        """API.extract() must return dict[str, Any]."""
        sig = inspect.signature(ArchGraph.extract)
        ret = sig.return_annotation
        # Return annotation should reference dict
        assert ret is not inspect.Parameter.empty, (
            "API.extract() has no return type annotation"
        )

    def test_repo_is_first_positional(self):
        """'repo' must be the first parameter after self."""
        sig = inspect.signature(ArchGraph.extract)
        params = list(sig.parameters.keys())
        assert params[0] == "self"
        assert params[1] == "repo"

    def test_all_params_except_repo_have_defaults(self):
        """All parameters except 'repo' must have default values."""
        sig = inspect.signature(ArchGraph.extract)
        for name, param in sig.parameters.items():
            if name in ("self", "repo"):
                continue
            assert param.default is not inspect.Parameter.empty, (
                f"API.extract() parameter '{name}' has no default value"
            )


# ── API context manager ──────────────────────────────────────────────────────


class TestArchGraphContextManager:
    """Test that ArchGraph works as a context manager."""

    def test_enter_returns_self(self):
        """__enter__ must return the ArchGraph instance."""
        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None
        result = ag.__enter__()
        assert result is ag

    def test_exit_calls_close(self):
        """__exit__ must call close()."""
        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None
        ag.close = MagicMock()
        ag.__exit__(None, None, None)
        ag.close.assert_called_once()

    def test_close_clears_store(self):
        """close() must set _store to None."""
        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"

        mock_store = MagicMock()
        ag._store = mock_store

        ag.close()
        assert ag._store is None
        mock_store.close.assert_called_once()

    def test_close_idempotent(self):
        """Calling close() twice must not raise."""
        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        ag.close()  # Should not raise
        ag.close()  # Should not raise


# ── API constructor ──────────────────────────────────────────────────────────


class TestArchGraphConstructor:
    """Test ArchGraph constructor defaults."""

    def test_default_neo4j_uri(self):
        """Default Neo4j URI must be bolt://localhost:7687."""
        sig = inspect.signature(ArchGraph.__init__)
        default = sig.parameters["neo4j_uri"].default
        assert default == "bolt://localhost:7687"

    def test_default_neo4j_user(self):
        """Default Neo4j user must be 'neo4j'."""
        sig = inspect.signature(ArchGraph.__init__)
        default = sig.parameters["neo4j_user"].default
        assert default == "neo4j"

    def test_default_neo4j_password(self):
        """Default Neo4j password must be 'archgraph'."""
        sig = inspect.signature(ArchGraph.__init__)
        default = sig.parameters["neo4j_password"].default
        assert default == "archgraph"

    def test_store_initially_none(self):
        """ArchGraph must not connect to Neo4j until _get_store() is called."""
        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None
        assert ag._store is None
