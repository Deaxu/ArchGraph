"""Regression tests for fixed bugs.

Each test class corresponds to a specific issue that was found and fixed.
These tests prevent re-introduction of those bugs.
"""

from __future__ import annotations

import dataclasses
import inspect
import pathlib
import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.regression


# ── Helpers ──────────────────────────────────────────────────────────────────


def _assert_no_backslash_in_ids(graph, context: str = "") -> None:
    """Assert that no node IDs or file properties contain backslashes."""
    for node in graph.nodes:
        assert "\\" not in node.id, (
            f"Backslash in node ID ({context}): {node.id}"
        )
        if node.properties.get("file"):
            assert "\\" not in node.properties["file"], (
                f"Backslash in file property ({context}): {node.properties['file']}"
            )
        if node.properties.get("path"):
            assert "\\" not in node.properties["path"], (
                f"Backslash in path property ({context}): {node.properties['path']}"
            )


# ── Issue #1: Windows path separator mismatch ────────────────────────────────


class TestPathNormalization:
    """Issue #1: Node IDs must always use forward slashes, never backslashes.

    On Windows, pathlib and os.path produce backslash-separated paths by default.
    All node IDs and file properties must be normalized to forward slashes so that
    Cypher queries work consistently across platforms.
    """

    def test_treesitter_node_ids_no_backslash(self, tmp_multi_lang_project):
        """TreeSitter extractor must produce node IDs with forward slashes."""
        from archgraph.extractors.treesitter import TreeSitterExtractor

        ext = TreeSitterExtractor()
        graph = ext.extract(tmp_multi_lang_project)
        assert len(graph.nodes) > 0, "Expected at least one node from multi-lang project"
        _assert_no_backslash_in_ids(graph, "treesitter")

    def test_treesitter_c_only_no_backslash(self, tmp_c_project):
        """C-only extraction must produce forward-slash node IDs."""
        from archgraph.extractors.treesitter import TreeSitterExtractor

        ext = TreeSitterExtractor(languages=["c"])
        graph = ext.extract(tmp_c_project)
        assert len(graph.nodes) > 0
        _assert_no_backslash_in_ids(graph, "treesitter-c")

    def test_treesitter_rust_no_backslash(self, tmp_rust_project):
        """Rust extraction must produce forward-slash node IDs."""
        from archgraph.extractors.treesitter import TreeSitterExtractor

        ext = TreeSitterExtractor(languages=["rust"])
        graph = ext.extract(tmp_rust_project)
        assert len(graph.nodes) > 0
        _assert_no_backslash_in_ids(graph, "treesitter-rust")

    def test_annotation_node_ids_no_backslash(self, tmp_path):
        """Annotation extractor must produce node IDs with forward slashes."""
        from archgraph.extractors.annotations import AnnotationExtractor

        sub = tmp_path / "src" / "deep"
        sub.mkdir(parents=True)
        (sub / "todo.c").write_text(
            "// TODO: fix this\n// HACK: workaround\nvoid foo() {}\n"
        )
        ext = AnnotationExtractor()
        graph = ext.extract(tmp_path)
        assert len(graph.nodes) > 0, "Expected at least one annotation node"
        _assert_no_backslash_in_ids(graph, "annotation")

    def test_deep_analysis_node_ids_no_backslash(self, tmp_path):
        """Deep analysis must produce node IDs with forward slashes."""
        from archgraph.extractors.deep import TreeSitterDeepExtractor

        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "main.rs").write_text(textwrap.dedent("""\
            pub fn analyze(x: i32) -> i32 {
                if x > 0 { x + 1 } else { x - 1 }
            }

            pub fn process(data: &[u8]) -> Vec<u8> {
                let mut result = Vec::new();
                for &b in data {
                    result.push(b + 1);
                }
                result
            }
        """))
        ext = TreeSitterDeepExtractor(languages=["rust"])
        if not ext.available_languages:
            pytest.skip("Rust tree-sitter grammar not available")
        graph = ext.extract(tmp_path)
        # Deep analysis may or may not produce nodes depending on grammar
        # but if it does, they must have no backslashes
        _assert_no_backslash_in_ids(graph, "deep-analysis")

    def test_dependency_paths_no_backslash(self, tmp_path):
        """Dependency extractor paths must use forward slashes."""
        from archgraph.extractors.dependencies import DependencyExtractor

        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "package.json").write_text(
            '{"name":"test","dependencies":{"express":"^4.0.0","lodash":"^4.17.0"}}'
        )
        ext = DependencyExtractor()
        graph = ext.extract(tmp_path)
        assert len(graph.nodes) > 0, "Expected at least one dependency node"
        _assert_no_backslash_in_ids(graph, "dependency")

    def test_manifest_scan_paths_no_backslash(self, tmp_path):
        """Manifest file scanner must produce forward-slash relative paths."""
        from archgraph.manifest import scan_current_files

        sub = tmp_path / "src" / "utils"
        sub.mkdir(parents=True)
        (sub / "helper.c").write_text("void helper() {}\n")
        (sub / "util.h").write_text("#ifndef U_H\n#define U_H\n#endif\n")
        files = scan_current_files(tmp_path)
        assert len(files) > 0, "Expected at least one scanned file"
        for rel_path in files:
            assert "\\" not in rel_path, f"Backslash in manifest path: {rel_path}"

    def test_neo4j_get_source_normalizes_backslash_input(self):
        """Neo4jStore.get_source must normalize backslash in symbol_id to forward slash.

        Users on Windows may pass backslash-separated IDs; get_source must
        convert them before querying.
        """
        from archgraph.graph.neo4j_store import Neo4jStore

        store = Neo4jStore.__new__(Neo4jStore)
        store._uri = "bolt://localhost:7687"
        store._user = "neo4j"
        store._password = "test"
        store._database = "neo4j"
        store._driver = MagicMock()

        # Mock query to capture the params
        captured_params: list[dict] = []

        def fake_query(cypher: str, params: dict | None = None):
            captured_params.append(params or {})
            return [{"id": "func:src/main.c:foo:1", "body": "void foo() {}"}]

        store.query = fake_query  # type: ignore[assignment]

        store.get_source("func:src\\main.c:foo:1")
        assert len(captured_params) == 1
        assert captured_params[0]["id"] == "func:src/main.c:foo:1", (
            "get_source did not normalize backslash to forward slash"
        )

    def test_api_source_normalizes_backslash(self):
        """API.source() must normalize backslash in symbol_id."""
        from archgraph.api import ArchGraph

        ag = ArchGraph.__new__(ArchGraph)
        ag._uri = "bolt://localhost:7687"
        ag._user = "neo4j"
        ag._password = "test"
        ag._database = "neo4j"
        ag._store = None

        mock_store = MagicMock()
        mock_store.get_source.return_value = {"id": "func:src/main.c:foo:1", "body": "..."}
        ag._get_store = lambda: mock_store  # type: ignore[assignment]

        ag.source("func:src\\main.c:foo:1")
        mock_store.get_source.assert_called_once()
        call_arg = mock_store.get_source.call_args[0][0]
        assert "\\" not in call_arg, (
            f"API.source() did not normalize backslash: {call_arg}"
        )

    def test_api_impact_normalizes_backslash(self):
        """API.impact() must normalize backslash in symbol_id."""
        from archgraph.api import ArchGraph

        # Verify at the source level that normalization is present
        source_code = inspect.getsource(ArchGraph.impact)
        assert 'replace("\\\\", "/")' in source_code, (
            "API.impact() does not contain backslash normalization"
        )

    def test_api_context_normalizes_backslash(self):
        """API.context() must normalize backslash in symbol_id."""
        from archgraph.api import ArchGraph

        source_code = inspect.getsource(ArchGraph.context)
        assert 'replace("\\\\", "/")' in source_code, (
            "API.context() does not contain backslash normalization"
        )


# ── Issue #4: Git URL repo naming ─────────────────────────────────────────────


class TestGitUrlRepoNaming:
    """Issue #4: Git URL extract must use actual repo name, not generic 'repo'.

    When cloning from a git URL, the clone directory must be named after the
    actual repository, not a hardcoded fallback like 'repo'.
    """

    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://github.com/user/project.git", "project"),
            ("https://github.com/user/project", "project"),
            ("https://github.com/user/project/", "project"),
            ("git@github.com:user/my-repo.git", "my-repo"),
            ("ssh://git@github.com/user/test-repo.git", "test-repo"),
            ("https://gitlab.com/group/subgroup/repo.git", "repo"),
            ("https://github.com/user/MY-PROJECT.git", "MY-PROJECT"),
            ("https://github.com/user/project123", "project123"),
        ],
    )
    def test_repo_name_extraction(self, url: str, expected: str) -> None:
        """_repo_name_from_url must extract the repo name correctly."""
        from archgraph.cli import _repo_name_from_url

        assert _repo_name_from_url(url) == expected

    def test_empty_url_fallback(self) -> None:
        """Empty URL must fall back to 'repo'."""
        from archgraph.cli import _repo_name_from_url

        result = _repo_name_from_url("")
        assert result == "repo", f"Expected 'repo' fallback, got '{result}'"

    def test_trailing_slash_stripped(self) -> None:
        """Trailing slash must not become part of the repo name."""
        from archgraph.cli import _repo_name_from_url

        result = _repo_name_from_url("https://github.com/user/project/")
        assert result == "project"
        assert result != ""

    def test_dot_git_suffix_stripped(self) -> None:
        """The .git suffix must be stripped from the repo name."""
        from archgraph.cli import _repo_name_from_url

        result = _repo_name_from_url("https://github.com/user/mylib.git")
        assert result == "mylib"
        assert not result.endswith(".git")

    def test_ssh_style_colon_path(self) -> None:
        """SSH-style git@host:user/repo URLs must be parsed correctly."""
        from archgraph.cli import _repo_name_from_url

        result = _repo_name_from_url("git@github.com:user/mylib.git")
        assert result == "mylib"

    def test_name_not_empty_for_various_urls(self) -> None:
        """No valid URL should produce an empty repo name."""
        from archgraph.cli import _repo_name_from_url

        urls = [
            "https://github.com/user/project.git",
            "git@github.com:user/project.git",
            "ssh://git@github.com/user/project.git",
            "https://github.com/user/project",
        ]
        for url in urls:
            name = _repo_name_from_url(url)
            assert name, f"Empty repo name for URL: {url}"
            assert name != "repo", (
                f"Got fallback 'repo' for a valid URL: {url}"
            )

    def test_api_uses_repo_name_from_url(self) -> None:
        """API extract() must use _repo_name_from_url for cloned directory naming."""
        source_code = inspect.getsource(
            __import__("archgraph.api", fromlist=["ArchGraph"]).ArchGraph.extract
        )
        assert "_repo_name_from_url" in source_code, (
            "API.extract() does not call _repo_name_from_url"
        )


# ── Issues #5, #6: Config consistency ────────────────────────────────────────


class TestConfigConsistency:
    """Issues #5, #6: CLI, API, and MCP must have consistent defaults and parameters.

    The API, CLI, and MCP surfaces must all expose the same parameters with
    matching default values. Drift between these interfaces leads to confusing
    behavior where the same extraction produces different results depending on
    which interface is used.
    """

    def test_api_include_clang_default_matches_cli(self) -> None:
        """include_clang must default to True in API (matching CLI and config)."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        default = sig.parameters["include_clang"].default
        assert default is True, (
            f"API include_clang default is {default!r}, expected True"
        )

    def test_api_include_deep_default_matches_cli(self) -> None:
        """include_deep must default to True in API (matching CLI and config)."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        default = sig.parameters["include_deep"].default
        assert default is True, (
            f"API include_deep default is {default!r}, expected True"
        )

    def test_api_include_cve_default_matches_cli(self) -> None:
        """include_cve must default to False in API (matching CLI and config)."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        default = sig.parameters["include_cve"].default
        assert default is False, (
            f"API include_cve default is {default!r}, expected False"
        )

    def test_api_workers_default_is_zero(self) -> None:
        """workers must default to 0 (auto) in API (matching CLI and config)."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        default = sig.parameters["workers"].default
        assert default == 0, f"API workers default is {default!r}, expected 0"

    def test_api_max_body_size_default_matches_config(self) -> None:
        """max_body_size must default to 51200 in API (matching ExtractConfig)."""
        from archgraph.api import ArchGraph
        from archgraph.config import ExtractConfig

        api_sig = inspect.signature(ArchGraph.extract)
        api_default = api_sig.parameters["max_body_size"].default

        config_fields = {f.name: f for f in dataclasses.fields(ExtractConfig)}
        config_default = config_fields["max_body_size"].default

        assert api_default == config_default, (
            f"API max_body_size default ({api_default}) != "
            f"ExtractConfig default ({config_default})"
        )

    def test_api_has_workers_param(self) -> None:
        """API extract() must accept a 'workers' parameter."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        assert "workers" in sig.parameters, "API.extract() missing 'workers' parameter"

    def test_api_has_incremental_param(self) -> None:
        """API extract() must accept an 'incremental' parameter."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        assert "incremental" in sig.parameters, (
            "API.extract() missing 'incremental' parameter"
        )

    def test_api_has_max_body_size_param(self) -> None:
        """API extract() must accept a 'max_body_size' parameter."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        assert "max_body_size" in sig.parameters, (
            "API.extract() missing 'max_body_size' parameter"
        )

    def test_api_has_branch_depth_params(self) -> None:
        """API extract() must accept 'branch' and 'depth' parameters."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        assert "branch" in sig.parameters, "API.extract() missing 'branch' parameter"
        assert "depth" in sig.parameters, "API.extract() missing 'depth' parameter"

    def test_api_has_include_scip_param(self) -> None:
        """API extract() must accept 'include_scip' parameter."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        assert "include_scip" in sig.parameters, (
            "API.extract() missing 'include_scip' parameter"
        )

    def test_api_has_include_body_param(self) -> None:
        """API extract() must accept 'include_body' parameter."""
        from archgraph.api import ArchGraph

        sig = inspect.signature(ArchGraph.extract)
        assert "include_body" in sig.parameters, (
            "API.extract() missing 'include_body' parameter"
        )

    def test_all_extract_config_fields_in_api(self) -> None:
        """API extract() must accept all user-facing ExtractConfig fields.

        Internal fields (neo4j connection, OSV batch size, etc.) are excluded,
        but every user-facing config knob must have a corresponding API parameter.
        """
        from archgraph.api import ArchGraph
        from archgraph.config import ExtractConfig

        api_params = set(inspect.signature(ArchGraph.extract).parameters.keys())
        api_params -= {"self", "repo"}
        config_fields = {f.name for f in dataclasses.fields(ExtractConfig)}

        # Internal / connection fields not exposed to the user
        internal = {
            "repo_path",
            "neo4j_uri",
            "neo4j_user",
            "neo4j_password",
            "neo4j_database",
            "osv_batch_size",
            "include_skills",
            "max_file_size",
            "git_max_commits",
            "clang_extra_args",
        }
        expected = config_fields - internal

        # Map API param names to config field names where they differ
        api_mapped = set(api_params)
        if "compile_commands" in api_mapped:
            api_mapped.discard("compile_commands")
            api_mapped.add("clang_compile_commands")
        # clear_db is API-only (not a config field), remove it
        api_mapped.discard("clear_db")
        # languages in API is a string, in config it's a list — same concept
        api_mapped.discard("languages")
        expected.discard("languages")

        missing = expected - api_mapped
        assert not missing, (
            f"API.extract() is missing ExtractConfig fields: {missing}"
        )

    def test_mcp_clear_db_default_is_false(self) -> None:
        """MCP handler must default clear_db to False (matching CLI)."""
        src = pathlib.Path("archgraph/mcp/server.py").read_text(encoding="utf-8")
        assert 'arguments.get("clear_db", False)' in src, (
            "MCP handler does not default clear_db to False"
        )

    def test_mcp_extract_schema_has_workers(self) -> None:
        """MCP extract tool schema must include 'workers' parameter."""
        src = pathlib.Path("archgraph/mcp/server.py").read_text(encoding="utf-8")
        assert '"workers"' in src, "MCP schema missing 'workers' parameter"

    def test_mcp_extract_schema_has_incremental(self) -> None:
        """MCP extract tool schema must include 'incremental' parameter."""
        src = pathlib.Path("archgraph/mcp/server.py").read_text(encoding="utf-8")
        assert '"incremental"' in src, "MCP schema missing 'incremental' parameter"

    def test_mcp_extract_schema_has_branch(self) -> None:
        """MCP extract tool schema must include 'branch' parameter."""
        src = pathlib.Path("archgraph/mcp/server.py").read_text(encoding="utf-8")
        assert '"branch"' in src, "MCP schema missing 'branch' parameter"

    def test_mcp_extract_schema_has_depth(self) -> None:
        """MCP extract tool schema must include 'depth' parameter."""
        src = pathlib.Path("archgraph/mcp/server.py").read_text(encoding="utf-8")
        assert '"depth"' in src, "MCP schema missing 'depth' parameter"

    def test_mcp_extract_schema_has_max_body_size(self) -> None:
        """MCP extract tool schema must include 'max_body_size' parameter."""
        src = pathlib.Path("archgraph/mcp/server.py").read_text(encoding="utf-8")
        assert '"max_body_size"' in src, "MCP schema missing 'max_body_size' parameter"

    def test_mcp_defaults_match_config_defaults(self) -> None:
        """MCP handler defaults must match ExtractConfig defaults for all boolean flags."""
        from archgraph.config import ExtractConfig

        src = pathlib.Path("archgraph/mcp/server.py").read_text(encoding="utf-8")

        # Verify key boolean defaults match between MCP and ExtractConfig
        checks = {
            "include_body": True,
            "include_git": True,
            "include_deps": True,
            "include_annotations": True,
            "include_deep": True,
            "include_clang": True,
            "include_scip": True,
            "include_cve": False,
            "include_clustering": False,
            "include_process": False,
        }

        config_fields = {f.name: f for f in dataclasses.fields(ExtractConfig)}

        for param, expected_default in checks.items():
            # Check config default
            assert config_fields[param].default == expected_default, (
                f"ExtractConfig.{param} default is {config_fields[param].default!r}, "
                f"expected {expected_default!r}"
            )
            # Check MCP handler uses matching default
            expected_str = f'arguments.get("{param}", {expected_default})'
            assert expected_str in src, (
                f"MCP handler does not have: {expected_str}"
            )

    def test_config_include_clang_default_is_true(self) -> None:
        """ExtractConfig.include_clang must default to True."""
        from archgraph.config import ExtractConfig

        config = ExtractConfig(repo_path=Path("."))
        assert config.include_clang is True

    def test_config_include_scip_default_is_true(self) -> None:
        """ExtractConfig.include_scip must default to True."""
        from archgraph.config import ExtractConfig

        config = ExtractConfig(repo_path=Path("."))
        assert config.include_scip is True

    def test_config_include_body_default_is_true(self) -> None:
        """ExtractConfig.include_body must default to True."""
        from archgraph.config import ExtractConfig

        config = ExtractConfig(repo_path=Path("."))
        assert config.include_body is True

    def test_config_max_body_size_default(self) -> None:
        """ExtractConfig.max_body_size must default to 51200."""
        from archgraph.config import ExtractConfig

        config = ExtractConfig(repo_path=Path("."))
        assert config.max_body_size == 51_200
