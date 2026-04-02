"""Tests for MCP server multi-repo state management."""

from unittest.mock import MagicMock, patch
import pytest

from archgraph.mcp.server import ArchGraphMCP


def _make_mcp() -> ArchGraphMCP:
    mcp = ArchGraphMCP.__new__(ArchGraphMCP)
    mcp._store = MagicMock()
    mcp._impact = MagicMock()
    mcp._cache = MagicMock()
    mcp._cache.get.return_value = None
    mcp._current_repo = None
    return mcp


class TestCurrentRepoState:

    @pytest.mark.asyncio
    async def test_use_repo_sets_current_repo(self) -> None:
        mcp = _make_mcp()
        from archgraph.registry import RepoEntry
        mock_entry = RepoEntry(name="fastify", path="/tmp/fastify", node_count=100, edge_count=200)

        with patch("archgraph.mcp.server.get_registry") as mock_reg:
            mock_reg.return_value.get.return_value = mock_entry
            result = await mcp.handle_tool_call("use_repo", {"name": "fastify"})

        assert mcp._current_repo == "fastify"
        assert result["active_repo"] == "fastify"

    @pytest.mark.asyncio
    async def test_use_repo_unknown_name_returns_error(self) -> None:
        mcp = _make_mcp()

        with patch("archgraph.mcp.server.get_registry") as mock_reg:
            mock_reg.return_value.get.return_value = None
            mock_reg.return_value.list_repos.return_value = []
            result = await mcp.handle_tool_call("use_repo", {"name": "unknown"})

        assert "error" in result
        assert mcp._current_repo is None

    @pytest.mark.asyncio
    async def test_search_without_active_repo_returns_error(self) -> None:
        mcp = _make_mcp()
        result = await mcp.handle_tool_call("search", {"name": "foo"})
        assert "error" in result
        assert "use_repo" in result["error"]

    @pytest.mark.asyncio
    async def test_repos_shows_active_flag(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = "fastify"
        from archgraph.registry import RepoEntry
        entries = [
            RepoEntry(name="fastify", path="/tmp/fastify"),
            RepoEntry(name="usb", path="/tmp/usb"),
        ]
        with patch("archgraph.mcp.server.get_registry") as mock_reg:
            mock_reg.return_value.list_repos.return_value = entries
            result = await mcp.handle_tool_call("repos", {})

        active = [r for r in result if r["name"] == "fastify"]
        inactive = [r for r in result if r["name"] == "usb"]
        assert active[0]["active"] is True
        assert inactive[0]["active"] is False


class TestAutoRepoFilter:

    @pytest.mark.asyncio
    async def test_search_filters_by_active_repo(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = "fastify"
        mcp._store.query.return_value = []

        await mcp.handle_tool_call("search", {"name": "route"})

        cypher = mcp._store.query.call_args[0][0]
        params = mcp._store.query.call_args[0][1]
        assert "repo" in cypher
        assert params.get("repo") == "fastify"

    @pytest.mark.asyncio
    async def test_query_requires_active_repo(self) -> None:
        mcp = _make_mcp()
        result = await mcp.handle_tool_call("query", {"cypher": "MATCH (n) RETURN n"})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_query_injects_repo_param(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = "fastify"
        mcp._store.query.return_value = []

        await mcp.handle_tool_call("query", {"cypher": "MATCH (n {repo: $_repo}) RETURN n"})

        params = mcp._store.query.call_args[0][1]
        assert params.get("_repo") == "fastify"

    @pytest.mark.asyncio
    async def test_stats_filtered_by_repo(self) -> None:
        mcp = _make_mcp()
        mcp._current_repo = "fastify"
        mcp._store.stats.return_value = {"nodes": {}, "edges": {}}
        mcp._store.query.return_value = [{"count": 0}]

        await mcp.handle_tool_call("stats", {})

        mcp._store.stats.assert_called_once_with(repo="fastify")
