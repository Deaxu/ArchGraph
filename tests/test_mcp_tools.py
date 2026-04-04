"""Tests for MCP server tool handlers — each tool's behavior and edge cases."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from archgraph.mcp.server import ArchGraphMCP

pytestmark = pytest.mark.mcp


def _make_mcp() -> ArchGraphMCP:
    """Create MCP instance with mocked Neo4j store and impact analyzer."""
    mcp = ArchGraphMCP.__new__(ArchGraphMCP)
    mcp._store = MagicMock()
    mcp._impact = MagicMock()
    mcp._current_repo = "test-repo"
    mcp._cache = MagicMock()
    mcp._cache.get.return_value = None  # no cache hits
    return mcp


# ── search ──────────────────────────────────────────────────────────────────


class TestMCPSearch:
    """Test MCP search tool handler."""

    @pytest.mark.asyncio
    async def test_search_by_name(self) -> None:
        """search tool with name should return matching symbols."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [
            {"id": "func:main.c:foo:1", "name": "foo", "labels": ["Function"], "file": "main.c", "line": 1}
        ]
        result = await mcp.handle_tool_call("search", {"name": "foo"})
        assert len(result) == 1
        assert result[0]["name"] == "foo"

    @pytest.mark.asyncio
    async def test_search_with_type_filter(self) -> None:
        """search with type='function' should query with Function label."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "test", "type": "function"})
        cypher = mcp._store.query.call_args[0][0]
        assert ":Function" in cypher

    @pytest.mark.asyncio
    async def test_search_with_class_type(self) -> None:
        """search with type='class' should query with Class label."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "MyClass", "type": "class"})
        cypher = mcp._store.query.call_args[0][0]
        assert ":Class" in cypher

    @pytest.mark.asyncio
    async def test_search_unknown_type_returns_error(self) -> None:
        """search with unknown type should return an error."""
        mcp = _make_mcp()
        result = await mcp.handle_tool_call("search", {"name": "x", "type": "widget"})
        # _handle_search returns [{"error": ...}] for unknown types
        assert any("error" in r for r in result if isinstance(r, dict))

    @pytest.mark.asyncio
    async def test_search_wildcard(self) -> None:
        """search with 'parse*' should use regex matching (=~)."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "parse*"})
        cypher = mcp._store.query.call_args[0][0]
        assert "=~" in cypher

    @pytest.mark.asyncio
    async def test_search_plain_name_uses_contains(self) -> None:
        """search with a plain name (no wildcard) should use CONTAINS."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "validate"})
        cypher = mcp._store.query.call_args[0][0]
        assert "CONTAINS" in cypher

    @pytest.mark.asyncio
    async def test_search_with_file_pattern(self) -> None:
        """search with file_pattern should filter by file path."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "foo", "file_pattern": "src/auth*"})
        cypher = mcp._store.query.call_args[0][0]
        params = mcp._store.query.call_args[0][1]
        # file_pattern with wildcard should use regex
        assert "file" in cypher.lower()
        assert "=~" in cypher
        assert "file_regex" in params

    @pytest.mark.asyncio
    async def test_search_with_limit(self) -> None:
        """search should pass limit to query params."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "foo", "limit": 5})
        params = mcp._store.query.call_args[0][1]
        assert params["limit"] == 5

    @pytest.mark.asyncio
    async def test_search_default_limit_is_20(self) -> None:
        """search without explicit limit should default to 20."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "foo"})
        params = mcp._store.query.call_args[0][1]
        assert params["limit"] == 20

    @pytest.mark.asyncio
    async def test_search_filters_by_active_repo(self) -> None:
        """search should include repo filter in Cypher query."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "route"})
        cypher = mcp._store.query.call_args[0][0]
        params = mcp._store.query.call_args[0][1]
        assert "repo" in cypher
        assert params.get("repo") == "test-repo"

    @pytest.mark.asyncio
    async def test_search_no_type_uses_node_label(self) -> None:
        """search without type should use the generic _Node label."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search", {"name": "foo"})
        cypher = mcp._store.query.call_args[0][0]
        assert ":_Node" in cypher


# ── source ──────────────────────────────────────────────────────────────────


class TestMCPSource:
    """Test MCP source tool handler."""

    @pytest.mark.asyncio
    async def test_source_returns_body(self) -> None:
        """source tool should return function body from Neo4j store."""
        mcp = _make_mcp()
        mcp._store.get_source.return_value = {
            "id": "func:main.c:foo:1",
            "name": "foo",
            "body": "void foo() { return; }",
            "file": "main.c",
        }
        result = await mcp.handle_tool_call("source", {"symbol_id": "func:main.c:foo:1"})
        assert result["body"] == "void foo() { return; }"
        assert result["name"] == "foo"

    @pytest.mark.asyncio
    async def test_source_not_found_returns_error(self) -> None:
        """source tool should return error for unknown symbol."""
        mcp = _make_mcp()
        mcp._store.get_source.return_value = None
        result = await mcp.handle_tool_call("source", {"symbol_id": "func:nonexistent:1"})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_source_passes_repo(self) -> None:
        """source tool should pass active repo to get_source."""
        mcp = _make_mcp()
        mcp._store.get_source.return_value = {"id": "x", "name": "x", "body": "x", "file": "x"}
        await mcp.handle_tool_call("source", {"symbol_id": "func:a.c:x:1"})
        mcp._store.get_source.assert_called_once_with("func:a.c:x:1", repo="test-repo")

    @pytest.mark.asyncio
    async def test_source_normalizes_backslash(self) -> None:
        """source tool should convert backslashes to forward slashes in symbol_id."""
        mcp = _make_mcp()
        mcp._store.get_source.return_value = {"id": "func:src/a.c:x:1", "name": "x", "body": "x", "file": "x"}
        await mcp.handle_tool_call("source", {"symbol_id": "func:src\\a.c:x:1"})
        # The first positional arg should have forward slashes
        called_id = mcp._store.get_source.call_args[0][0]
        assert "\\" not in called_id


# ── impact ──────────────────────────────────────────────────────────────────


class TestMCPImpact:
    """Test MCP impact tool handler."""

    @pytest.mark.asyncio
    async def test_impact_symbol_not_found(self) -> None:
        """impact tool should return error if symbol does not exist."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []  # symbol not found
        result = await mcp.handle_tool_call("impact", {"symbol_id": "func:missing:1"})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_impact_delegates_to_analyzer(self) -> None:
        """impact tool should call ImpactAnalyzer when symbol exists."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [{"n._id": "func:a.c:main:1"}]  # symbol found
        mcp._impact.analyze_impact.return_value = {
            "symbol": "func:a.c:main:1",
            "total_affected": 3,
        }
        await mcp.handle_tool_call("impact", {"symbol_id": "func:a.c:main:1"})
        mcp._impact.analyze_impact.assert_called_once()

    @pytest.mark.asyncio
    async def test_impact_passes_direction(self) -> None:
        """impact tool should pass direction parameter to analyzer."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [{"n._id": "func:a.c:main:1"}]
        mcp._impact.analyze_impact.return_value = {"total_affected": 0}
        await mcp.handle_tool_call(
            "impact",
            {"symbol_id": "func:a.c:main:1", "direction": "downstream"},
        )
        call_args = mcp._impact.analyze_impact.call_args
        assert call_args[0][1] == "downstream"

    @pytest.mark.asyncio
    async def test_impact_passes_max_depth(self) -> None:
        """impact tool should pass max_depth parameter to analyzer."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [{"n._id": "func:a.c:main:1"}]
        mcp._impact.analyze_impact.return_value = {"total_affected": 0}
        await mcp.handle_tool_call(
            "impact",
            {"symbol_id": "func:a.c:main:1", "max_depth": 10},
        )
        call_args = mcp._impact.analyze_impact.call_args
        assert call_args[0][2] == 10

    @pytest.mark.asyncio
    async def test_impact_default_direction_upstream(self) -> None:
        """impact tool default direction should be 'upstream'."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [{"n._id": "func:a.c:main:1"}]
        mcp._impact.analyze_impact.return_value = {"total_affected": 0}
        await mcp.handle_tool_call("impact", {"symbol_id": "func:a.c:main:1"})
        call_args = mcp._impact.analyze_impact.call_args
        assert call_args[0][1] == "upstream"


# ── context ─────────────────────────────────────────────────────────────────


class TestMCPContext:
    """Test MCP context tool handler."""

    @pytest.mark.asyncio
    async def test_context_symbol_not_found(self) -> None:
        """context tool should return error for unknown symbol."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        result = await mcp.handle_tool_call("context", {"symbol_id": "func:missing:1"})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_context_returns_structured_data(self) -> None:
        """context tool should return callers, callees, cluster, security."""
        mcp = _make_mcp()
        # First query: symbol lookup
        # Subsequent queries: callers, callees, cluster, processes
        mcp._store.query.side_effect = [
            [{"props": {"name": "foo", "file": "a.c", "is_input_source": True}}],  # symbol
            [{"id": "func:a.c:bar:5", "name": "bar", "file": "a.c"}],  # callers
            [],  # callees
            [],  # cluster
            [],  # processes
        ]
        result = await mcp.handle_tool_call("context", {"symbol_id": "func:a.c:foo:1"})
        assert "symbol" in result
        assert "callers" in result
        assert "callees" in result
        assert "security_labels" in result
        assert result["security_labels"].get("is_input_source") is True

    @pytest.mark.asyncio
    async def test_context_strips_body_from_props(self) -> None:
        """context tool should strip 'body' from symbol properties (served via source tool)."""
        mcp = _make_mcp()
        mcp._store.query.side_effect = [
            [{"props": {"name": "foo", "file": "a.c", "body": "void foo() {}"}}],
            [], [], [], [],
        ]
        result = await mcp.handle_tool_call("context", {"symbol_id": "func:a.c:foo:1"})
        # body should be stripped
        assert "body" not in result["symbol"]["properties"]


# ── stats ───────────────────────────────────────────────────────────────────


class TestMCPStats:
    """Test MCP stats tool handler."""

    @pytest.mark.asyncio
    async def test_stats_calls_store(self) -> None:
        """stats tool should query Neo4j for counts."""
        mcp = _make_mcp()
        mcp._store.stats.return_value = {"nodes": {"Function": 10}, "edges": {"CALLS": 5}}
        mcp._store.query.return_value = [{"count": 0}]
        result = await mcp.handle_tool_call("stats", {})
        mcp._store.stats.assert_called_once_with(repo="test-repo")
        assert "graph_stats" in result

    @pytest.mark.asyncio
    async def test_stats_includes_cluster_and_process_counts(self) -> None:
        """stats should include cluster and process counts."""
        mcp = _make_mcp()
        mcp._store.stats.return_value = {"nodes": {}, "edges": {}}
        mcp._store.query.side_effect = [
            [{"count": 3}],   # clusters
            [{"count": 2}],   # processes
        ]
        result = await mcp.handle_tool_call("stats", {})
        assert result["clusters"] == 3
        assert result["processes"] == 2


# ── query / cypher ──────────────────────────────────────────────────────────


class TestMCPQuery:
    """Test MCP query and cypher tool handlers."""

    @pytest.mark.asyncio
    async def test_query_injects_repo_param(self) -> None:
        """query tool should inject _repo parameter."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("query", {"cypher": "MATCH (n {repo: $_repo}) RETURN n"})
        params = mcp._store.query.call_args[0][1]
        assert params.get("_repo") == "test-repo"

    @pytest.mark.asyncio
    async def test_cypher_is_alias_for_query(self) -> None:
        """cypher tool should behave identically to query tool."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [{"n": "result"}]
        result = await mcp.handle_tool_call(
            "cypher", {"query": "MATCH (n) RETURN n LIMIT 1"}
        )
        assert result == [{"n": "result"}]

    @pytest.mark.asyncio
    async def test_query_requires_active_repo(self) -> None:
        """query tool should fail without active repo."""
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("query", {"cypher": "MATCH (n) RETURN n"})
        assert "error" in result


# ── use_repo ────────────────────────────────────────────────────────────────


class TestMCPUseRepo:
    """Test MCP use_repo tool handler."""

    @pytest.mark.asyncio
    async def test_use_repo_sets_current_repo(self) -> None:
        """use_repo should set _current_repo on success."""
        mcp = _make_mcp()
        mcp._current_repo = None
        from archgraph.registry import RepoEntry
        mock_entry = RepoEntry(name="myrepo", path="/tmp/myrepo", node_count=50, edge_count=100)

        with patch("archgraph.mcp.server.get_registry") as mock_reg:
            mock_reg.return_value.get.return_value = mock_entry
            result = await mcp.handle_tool_call("use_repo", {"name": "myrepo"})

        assert mcp._current_repo == "myrepo"
        assert result["active_repo"] == "myrepo"

    @pytest.mark.asyncio
    async def test_use_repo_unknown_returns_error(self) -> None:
        """use_repo with unknown name should return error."""
        mcp = _make_mcp()
        mcp._current_repo = None

        with patch("archgraph.mcp.server.get_registry") as mock_reg:
            mock_reg.return_value.get.return_value = None
            mock_reg.return_value.list_repos.return_value = []
            result = await mcp.handle_tool_call("use_repo", {"name": "unknown"})

        assert "error" in result
        assert mcp._current_repo is None

    @pytest.mark.asyncio
    async def test_use_repo_empty_name_returns_error(self) -> None:
        """use_repo with empty name should return error."""
        mcp = _make_mcp()
        result = await mcp.handle_tool_call("use_repo", {"name": ""})
        assert "error" in result


# ── repos ───────────────────────────────────────────────────────────────────


class TestMCPRepos:
    """Test MCP repos tool handler."""

    @pytest.mark.asyncio
    async def test_repos_shows_active_flag(self) -> None:
        """repos tool should mark the active repo with active=True."""
        mcp = _make_mcp()
        mcp._current_repo = "repoA"
        from archgraph.registry import RepoEntry
        entries = [
            RepoEntry(name="repoA", path="/tmp/a"),
            RepoEntry(name="repoB", path="/tmp/b"),
        ]
        with patch("archgraph.mcp.server.get_registry") as mock_reg:
            mock_reg.return_value.list_repos.return_value = entries
            result = await mcp.handle_tool_call("repos", {})

        active = [r for r in result if r["name"] == "repoA"]
        inactive = [r for r in result if r["name"] == "repoB"]
        assert active[0]["active"] is True
        assert inactive[0]["active"] is False


# ── search_calls ────────────────────────────────────────────────────────────


class TestMCPSearchCalls:
    """Test MCP search_calls tool handler."""

    @pytest.mark.asyncio
    async def test_search_calls_by_caller(self) -> None:
        """search_calls with caller should filter by caller name."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [
            {"caller": "main", "caller_file": "a.c", "target": "foo", "target_file": "b.c"}
        ]
        result = await mcp.handle_tool_call("search_calls", {"caller": "main"})
        cypher = mcp._store.query.call_args[0][0]
        assert "CALLS" in cypher
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_search_calls_by_target(self) -> None:
        """search_calls with target should filter by target name."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search_calls", {"target": "validate"})
        params = mcp._store.query.call_args[0][1]
        assert params.get("target") == "validate"

    @pytest.mark.asyncio
    async def test_search_calls_resolved_only(self) -> None:
        """search_calls with resolved_only should add resolved filter."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search_calls", {"caller": "main", "resolved_only": True})
        cypher = mcp._store.query.call_args[0][0]
        assert "resolved" in cypher

    @pytest.mark.asyncio
    async def test_search_calls_scip_source_filter(self) -> None:
        """search_calls with source='scip' should filter by source."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search_calls", {"caller": "main", "source": "scip"})
        cypher = mcp._store.query.call_args[0][0]
        assert "scip" in cypher

    @pytest.mark.asyncio
    async def test_search_calls_transitive(self) -> None:
        """search_calls with max_depth > 1 should use variable-length path."""
        mcp = _make_mcp()
        mcp._store.query.return_value = []
        await mcp.handle_tool_call("search_calls", {"caller": "main", "max_depth": 3})
        cypher = mcp._store.query.call_args[0][0]
        assert "*1..3" in cypher  # variable-length pattern


# ── detect_changes ──────────────────────────────────────────────────────────


class TestMCPDetectChanges:
    """Test MCP detect_changes tool handler."""

    @pytest.mark.asyncio
    async def test_detect_changes_delegates_to_impact(self) -> None:
        """detect_changes should delegate to ImpactAnalyzer."""
        mcp = _make_mcp()
        mcp._impact.analyze_change_impact.return_value = {"affected": []}
        files = ["src/auth.c", "src/main.c"]
        await mcp.handle_tool_call("detect_changes", {"changed_files": files})
        mcp._impact.analyze_change_impact.assert_called_once_with(
            files, repo_name="test-repo"
        )


# ── find_vulnerabilities ───────────────────────────────────────────────────


class TestMCPFindVulnerabilities:
    """Test MCP find_vulnerabilities tool handler."""

    @pytest.mark.asyncio
    async def test_find_vulns_returns_all(self) -> None:
        """find_vulnerabilities without severity returns all."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [
            {"dependency": "openssl", "version": "1.1.1", "vuln_id": "CVE-2023-1234",
             "summary": "Buffer overflow", "severity": "CRITICAL"},
        ]
        result = await mcp.handle_tool_call("find_vulnerabilities", {})
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_find_vulns_filters_by_severity(self) -> None:
        """find_vulnerabilities with severity should filter results."""
        mcp = _make_mcp()
        mcp._store.query.return_value = [
            {"dependency": "openssl", "version": "1.1.1", "vuln_id": "CVE-2023-1234",
             "summary": "Buffer overflow", "severity": "CRITICAL"},
            {"dependency": "curl", "version": "7.0", "vuln_id": "CVE-2023-5678",
             "summary": "Redirect", "severity": "LOW"},
        ]
        result = await mcp.handle_tool_call("find_vulnerabilities", {"severity": "CRITICAL"})
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"


# ── require_repo (cross-cutting) ───────────────────────────────────────────


class TestMCPRequireRepo:
    """Test that tools requiring an active repo fail properly without one."""

    @pytest.mark.asyncio
    async def test_search_without_repo_fails(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("search", {"name": "test"})
        assert isinstance(result, dict) and "error" in result

    @pytest.mark.asyncio
    async def test_context_without_repo_fails(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("context", {"symbol_id": "func:a:b:1"})
        assert isinstance(result, dict) and "error" in result

    @pytest.mark.asyncio
    async def test_impact_without_repo_fails(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("impact", {"symbol_id": "func:a:b:1"})
        assert isinstance(result, dict) and "error" in result

    @pytest.mark.asyncio
    async def test_source_without_repo_fails(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("source", {"symbol_id": "func:a:b:1"})
        assert isinstance(result, dict) and "error" in result

    @pytest.mark.asyncio
    async def test_stats_without_repo_fails(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("stats", {})
        assert isinstance(result, dict) and "error" in result

    @pytest.mark.asyncio
    async def test_detect_changes_without_repo_fails(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("detect_changes", {"changed_files": ["a.c"]})
        assert isinstance(result, dict) and "error" in result

    @pytest.mark.asyncio
    async def test_search_calls_without_repo_fails(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("search_calls", {"caller": "main"})
        assert isinstance(result, dict) and "error" in result

    @pytest.mark.asyncio
    async def test_find_vulnerabilities_without_repo_fails(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = None
        result = await mcp.handle_tool_call("find_vulnerabilities", {})
        assert isinstance(result, dict) and "error" in result


# ── unknown tool ────────────────────────────────────────────────────────────


class TestMCPUnknownTool:
    """Test unknown tool name handling."""

    @pytest.mark.asyncio
    async def test_unknown_tool_returns_error(self) -> None:
        mcp = _make_mcp()
        result = await mcp.handle_tool_call("nonexistent_tool", {})
        assert isinstance(result, dict) and "error" in result
        assert "Unknown tool" in result["error"]


# ── caching ─────────────────────────────────────────────────────────────────


class TestMCPCaching:
    """Test MCP tool result caching behavior."""

    @pytest.mark.asyncio
    async def test_cache_hit_returns_cached_value(self) -> None:
        """When cache has a hit, store.query should not be called."""
        mcp = _make_mcp()
        cached_result = [{"id": "cached", "name": "cached_func"}]
        mcp._cache.get.return_value = cached_result
        result = await mcp.handle_tool_call("search", {"name": "foo"})
        assert result == cached_result
        mcp._store.query.assert_not_called()

    @pytest.mark.asyncio
    async def test_detect_changes_not_cached(self) -> None:
        """detect_changes should bypass cache."""
        mcp = _make_mcp()
        mcp._cache.get.return_value = {"old": "data"}
        mcp._impact.analyze_change_impact.return_value = {"fresh": "result"}
        result = await mcp.handle_tool_call(
            "detect_changes", {"changed_files": ["a.c"]}
        )
        # detect_changes is in the no-cache list, so it should call the analyzer
        assert result == {"fresh": "result"}

    @pytest.mark.asyncio
    async def test_use_repo_not_cached(self) -> None:
        """use_repo should bypass cache."""
        mcp = _make_mcp()
        mcp._current_repo = None
        mcp._cache.get.return_value = {"stale": True}
        from archgraph.registry import RepoEntry
        with patch("archgraph.mcp.server.get_registry") as mock_reg:
            mock_reg.return_value.get.return_value = RepoEntry(
                name="myrepo", path="/tmp/myrepo"
            )
            result = await mcp.handle_tool_call("use_repo", {"name": "myrepo"})
        assert result["active_repo"] == "myrepo"
