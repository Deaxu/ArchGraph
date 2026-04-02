# Multi-Repo Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-repo isolation to Neo4j so each node carries a `repo` property, and the MCP server enforces an active-repo context — no tool works without calling `use_repo` first.

**Architecture:** Every node gets `repo: str` injected at import time. `ArchGraphMCP` holds `_current_repo: str | None`; all tool handlers call `_require_repo()` which raises if unset. A new `use_repo` tool sets the active repo; `extract` sets it automatically on success.

**Tech Stack:** Python 3.11, Neo4j (bolt), `archgraph` package, `pytest`, `unittest.mock`

---

## File Map

| File | Change |
|------|--------|
| `archgraph/graph/neo4j_store.py` | `import_graph(repo_name)`, `clear_repo()`, `stats(repo)`, `get_source(repo)`, repo index |
| `archgraph/tool/impact.py` | `analyze_change_impact(repo_name)` — add repo filter to Cypher |
| `archgraph/mcp/server.py` | `_current_repo` state, `use_repo` tool, auto-filter in all handlers, cache key fix, extract auto-set |
| `archgraph/cli.py` | Pass `repo_name` to `import_graph` (lines 242, 268) |
| `archgraph/api.py` | Pass `repo_name` to `import_graph` (line 134) |
| `tests/test_neo4j_mock.py` | Tests for `repo` injection and `clear_repo` |
| `tests/test_mcp_multirepo.py` | New file — MCP multi-repo behavior tests |

---

## Task 1: `repo` property injection + `clear_repo` in Neo4jStore

**Files:**
- Modify: `archgraph/graph/neo4j_store.py`
- Test: `tests/test_neo4j_mock.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_neo4j_mock.py`:

```python
from archgraph.graph.schema import GraphData, Node


class TestRepoIsolation:
    """Test repo property injection and per-repo clear."""

    def _make_store(self) -> Neo4jStore:
        store = Neo4jStore(uri="bolt://mock:7687")
        store._driver = MagicMock()
        store._apoc_available = False  # force non-APOC path
        return store

    def _make_session(self, store: Neo4jStore) -> MagicMock:
        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        store._driver.session.return_value = session
        return session

    def test_import_graph_injects_repo_property(self) -> None:
        """import_graph adds repo property to every node record."""
        store = self._make_store()
        session = self._make_session(store)

        captured: list[list[dict]] = []
        session.run.side_effect = lambda q, **kw: captured.append(kw.get("records", []))

        node = Node(id="func:src/foo.py:bar:1", label="Function", properties={"name": "bar"})
        graph = GraphData(nodes=[node], edges=[])

        store.import_graph(graph, repo_name="my_repo")

        all_props = [r for batch in captured for r in batch]
        assert any(r.get("repo") == "my_repo" for r in all_props)

    def test_clear_repo_uses_repo_filter(self) -> None:
        """clear_repo only deletes nodes with matching repo property."""
        store = self._make_store()
        session = self._make_session(store)

        mock_result = MagicMock()
        mock_result.single.return_value = {"deleted": 0}
        session.run.return_value = mock_result

        store.clear_repo("my_repo")

        cypher = session.run.call_args[0][0]
        assert "repo" in cypher
        # Must NOT be a global delete (no bare MATCH (n) without filter)
        assert "MATCH (n)" not in cypher
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_neo4j_mock.py::TestRepoIsolation -v
```

Expected: `FAILED` — `import_graph` doesn't accept `repo_name`, `clear_repo` doesn't exist.

- [ ] **Step 3: Add `repo` index to `_INDEXES`**

In `archgraph/graph/neo4j_store.py`, find the `_INDEXES` list (line 17) and append:

```python
_INDEXES: list[tuple[str, list[str]]] = [
    ...
    (NodeLabel.DEPENDENCY, ["name"]),
    (NodeLabel.TAG, ["name"]),
    (NodeLabel.BASIC_BLOCK, ["function", "file"]),
    (NodeLabel.VULNERABILITY, ["vuln_id"]),
    (NodeLabel.CLUSTER, ["name"]),
    (NodeLabel.PROCESS, ["name"]),
    ("_Node", ["repo"]),   # ← add this line
]
```

- [ ] **Step 4: Add `clear_repo` method**

After the existing `clear` method (line 128), add:

```python
def clear_repo(self, repo_name: str) -> None:
    """Delete all nodes for a specific repo. Safer than clear()."""
    with self._session() as session:
        while True:
            result = session.run(
                "MATCH (n:_Node {repo: $repo}) "
                "WITH n LIMIT 10000 DETACH DELETE n "
                "RETURN count(*) AS deleted",
                repo=repo_name,
            )
            deleted = result.single()["deleted"]
            if deleted == 0:
                break
            logger.debug("Deleted batch of %d nodes for repo %s", deleted, repo_name)
    logger.info("Cleared graph data for repo: %s", repo_name)
```

- [ ] **Step 5: Update `import_graph` signature and thread `repo_name` through**

Replace the `import_graph` method (line 141–155):

```python
def import_graph(
    self, graph: GraphData, *, repo_name: str = "", use_create: bool = False,
) -> dict[str, int]:
    """Bulk import nodes and edges into Neo4j. Returns counts.

    Args:
        repo_name: Repository name tag written to every node's ``repo`` property.
        use_create: Use CREATE instead of MERGE. Much faster when the
                    database has been cleared beforehand.
    """
    if self._detect_apoc():
        return self._import_graph_apoc(graph, repo_name=repo_name)

    node_count = self._import_nodes(graph.nodes, repo_name=repo_name, use_create=use_create)
    edge_count = self._import_edges(graph.edges, use_create=use_create)
    return {"nodes_imported": node_count, "edges_imported": edge_count}
```

- [ ] **Step 6: Update `_import_nodes` to inject `repo` property**

Replace the `_import_nodes` method (line 157–198). The only change is the signature and adding `props["repo"] = repo_name` before appending to records:

```python
def _import_nodes(
    self, nodes: list[Node], *, repo_name: str = "", use_create: bool = False
) -> int:
    """Batch-import nodes."""
    if not nodes:
        return 0

    by_label: dict[str, list[Node]] = {}
    for node in nodes:
        by_label.setdefault(node.label, []).append(node)

    total = 0
    with self._session() as session:
        for label, label_nodes in by_label.items():
            for batch_start in range(0, len(label_nodes), NEO4J_BATCH_SIZE):
                batch = label_nodes[batch_start : batch_start + NEO4J_BATCH_SIZE]
                records = []
                for node in batch:
                    props = dict(node.properties)
                    props["_id"] = node.id
                    if repo_name:
                        props["repo"] = repo_name
                    records.append(props)

                if use_create:
                    session.run(
                        f"UNWIND $records AS props "
                        f"CREATE (n:{label}:_Node) "
                        f"SET n += props",
                        records=records,
                    )
                else:
                    session.run(
                        f"UNWIND $records AS props "
                        f"MERGE (n:{label} {{_id: props._id}}) "
                        f"SET n += props "
                        f"SET n:_Node",
                        records=records,
                    )
                total += len(batch)

            logger.debug("Imported %d %s nodes", len(label_nodes), label)

    logger.info("Imported %d nodes total", total)
    return total
```

- [ ] **Step 7: Update `_import_graph_apoc` and `_import_nodes_apoc`**

In `_import_graph_apoc` (line 244), update signature and pass through:

```python
def _import_graph_apoc(self, graph: GraphData, *, repo_name: str = "") -> dict[str, int]:
    """Import graph using APOC procedures for better performance."""
    node_count = self._import_nodes_apoc(graph.nodes, repo_name=repo_name)
    edge_count = self._import_edges_apoc(graph.edges)
    return {"nodes_imported": node_count, "edges_imported": edge_count}
```

In `_import_nodes_apoc` (line 250), update signature and add `if repo_name: props["repo"] = repo_name` after `props["_id"] = node.id`:

```python
def _import_nodes_apoc(self, nodes: list[Node], *, repo_name: str = "") -> int:
    """APOC-based parallel node import."""
    if not nodes:
        return 0

    by_label: dict[str, list[Node]] = {}
    for node in nodes:
        by_label.setdefault(node.label, []).append(node)

    total = 0
    with self._session() as session:
        for label, label_nodes in by_label.items():
            records = []
            for node in label_nodes:
                props = dict(node.properties)
                props["_id"] = node.id
                if repo_name:
                    props["repo"] = repo_name
                records.append(props)

            session.run(
                "CALL apoc.periodic.iterate("
                "  'UNWIND $records AS props RETURN props',"
                f"  'MERGE (n:{label} {{_id: props._id}}) SET n += props SET n:_Node',"
                "  {batchSize: 5000, parallel: true, params: {records: $records}}"
                ")",
                records=records,
            )
            total += len(label_nodes)
            logger.debug("APOC imported %d %s nodes", len(label_nodes), label)

    logger.info("APOC imported %d nodes total", total)
    return total
```

- [ ] **Step 8: Update `stats` and `get_source` to accept optional `repo` filter**

Replace `stats` method (line 437):

```python
def stats(self, repo: str | None = None) -> dict[str, Any]:
    """Return node and edge counts per type, optionally filtered by repo."""
    repo_filter = " {repo: $repo}" if repo else ""
    params: dict[str, Any] = {"repo": repo} if repo else {}
    with self._session() as session:
        node_result = session.run(
            f"MATCH (n:_Node{repo_filter}) "
            "WITH labels(n) AS lbls, count(*) AS cnt "
            "UNWIND lbls AS lbl "
            "RETURN lbl, sum(cnt) AS count "
            "ORDER BY count DESC",
            **params,
        )
        node_counts = {r["lbl"]: r["count"] for r in node_result}

        edge_result = session.run(
            f"MATCH (a:_Node{repo_filter})-[r]->() "
            "RETURN type(r) AS type, count(*) AS count "
            "ORDER BY count DESC",
            **params,
        )
        edge_counts = {r["type"]: r["count"] for r in edge_result}

    return {"nodes": node_counts, "edges": edge_counts}
```

Replace `get_source` method (line 402):

```python
def get_source(self, symbol_id: str, repo: str | None = None) -> dict[str, Any] | None:
    """Get source code for a symbol by its node ID."""
    repo_clause = " AND n.repo = $repo" if repo else ""
    params: dict[str, Any] = {"id": symbol_id}
    if repo:
        params["repo"] = repo
    results = self.query(
        f"MATCH (n:_Node {{_id: $id}}) WHERE n.body IS NOT NULL{repo_clause} "
        "RETURN n._id AS id, n.name AS name, n.file AS file, "
        "n.body AS body, n.body_lines AS body_lines, "
        "n.body_truncated AS body_truncated, "
        "n.line_start AS line_start, n.line_end AS line_end",
        params,
    )
    return results[0] if results else None
```

- [ ] **Step 9: Run tests to verify they pass**

```
pytest tests/test_neo4j_mock.py -v
```

Expected: all pass including `TestRepoIsolation`.

- [ ] **Step 10: Commit**

```bash
git add archgraph/graph/neo4j_store.py tests/test_neo4j_mock.py
git commit -m "feat: add repo property injection, clear_repo, and repo-filtered stats/source"
```

---

## Task 2: Update `import_graph` callers

**Files:**
- Modify: `archgraph/cli.py` (lines 242, 268)
- Modify: `archgraph/api.py` (line 134)

No new tests — existing test suite covers these paths.

- [ ] **Step 1: Fix skills-generation call in `cli.py` (line 242)**

Find this block:
```python
with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
    store.import_graph(graph)
    gen = SkillGenerator(store)
```

Change to:
```python
with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
    store.import_graph(graph, repo_name=resolved_path.name)
    gen = SkillGenerator(store)
```

- [ ] **Step 2: Fix main import call in `cli.py` (line 268)**

Find:
```python
result = store.import_graph(graph, use_create=clear_db)
```

Change to:
```python
result = store.import_graph(graph, repo_name=resolved_path.name, use_create=clear_db)
```

Also find the `store.clear()` call just above (line 262) and replace with:
```python
store.clear_repo(resolved_path.name)
```

- [ ] **Step 3: Fix `api.py` (line 134)**

Find:
```python
import_result = store.import_graph(graph)
```

Change to:
```python
import_result = store.import_graph(graph, repo_name=Path(self._repo_path).name)
```

Verify `Path` is already imported at the top of `api.py`. If not, add `from pathlib import Path`.

- [ ] **Step 4: Run full test suite**

```
pytest tests/ -v --tb=short -q
```

Expected: same pass/skip count as before (212 passed, 22 skipped).

- [ ] **Step 5: Commit**

```bash
git add archgraph/cli.py archgraph/api.py
git commit -m "feat: pass repo_name to import_graph in cli and api"
```

---

## Task 3: MCP server — `_current_repo`, `use_repo`, cache key, repos active field, extract auto-set

**Files:**
- Modify: `archgraph/mcp/server.py`
- Create: `tests/test_mcp_multirepo.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_mcp_multirepo.py`:

```python
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

    def test_initial_current_repo_is_none(self) -> None:
        mcp = ArchGraphMCP.__new__(ArchGraphMCP)
        mcp._store = MagicMock()
        mcp._impact = MagicMock()
        from archgraph.mcp.server import _ToolCache
        mcp._cache = _ToolCache()
        mcp._current_repo = None
        assert mcp._current_repo is None

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
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_mcp_multirepo.py -v
```

Expected: `FAILED` — `_current_repo`, `use_repo`, `active` field don't exist yet.

- [ ] **Step 3: Add `_current_repo` to `ArchGraphMCP.__init__`**

In `server.py`, find the `__init__` method (line 312). Add `self._current_repo` after `self._cache`:

```python
def __init__(
    self,
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_password: str = "archgraph",
    neo4j_database: str = "neo4j",
) -> None:
    self._store = Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database)
    self._impact = ImpactAnalyzer(self._store)
    self._cache = _ToolCache(ttl=60)
    self._current_repo: str | None = None
```

- [ ] **Step 4: Fix cache key to include active repo**

In `handle_tool_call` (line 329), replace the two cache lines:

Old:
```python
cached = self._cache.get(name, arguments)
```
New:
```python
cache_arguments = {**arguments, "__repo": self._current_repo}
cached = self._cache.get(name, cache_arguments)
```

And at the bottom of the method:

Old:
```python
self._cache.set(name, arguments, result)
```
New:
```python
self._cache.set(name, cache_arguments, result)
```

- [ ] **Step 5: Add `use_repo` to the TOOLS list**

In `server.py`, find the `TOOLS` list (after line 18) and add this entry before the closing `]`:

```python
{
    "name": "use_repo",
    "description": (
        "Set the active repository for all subsequent queries. "
        "Must be called before using search, context, impact, source, stats, "
        "detect_changes, query, or cypher. "
        "Use repos() to list available repository names."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Repository name as shown in repos() (e.g. 'fastify')",
            },
        },
        "required": ["name"],
    },
},
```

- [ ] **Step 6: Add `use_repo` case to `handle_tool_call`**

In `handle_tool_call`, add after the `elif name == "search_calls":` block:

```python
elif name == "use_repo":
    result = self._handle_use_repo(arguments)
```

- [ ] **Step 7: Add `_handle_use_repo` method**

Add after `_handle_repos` method:

```python
def _handle_use_repo(self, arguments: dict[str, Any]) -> dict[str, Any]:
    """Set the active repository for subsequent tool calls."""
    from archgraph.registry import get_registry
    name = arguments.get("name", "").strip()
    if not name:
        return {"error": "name is required"}
    entry = get_registry().get(name)
    if entry is None:
        available = [e.name for e in get_registry().list_repos()]
        return {
            "error": f"Repository {name!r} not found. Available: {available}",
        }
    self._current_repo = name
    return {
        "active_repo": name,
        "node_count": entry.node_count,
        "edge_count": entry.edge_count,
        "path": entry.path,
    }
```

- [ ] **Step 8: Update `_handle_repos` to add `active` field**

In `_handle_repos`, replace:
```python
return [e.to_dict() for e in entries]
```
With:
```python
return [{**e.to_dict(), "active": e.name == self._current_repo} for e in entries]
```

Also update the fallback path at the end of `_handle_repos` — wrap in try/except the same way, adding `"active": False` to fallback entries.

- [ ] **Step 9: Update `_handle_extract_sync` to use `clear_repo` and set `_current_repo`**

Replace the "Clear and import" block (lines 488–494):

Old:
```python
if clear_db:
    self._store.clear()
self._store.create_indexes()
import_start = time.time()
import_result = self._store.import_graph(graph)
```

New:
```python
repo_name = resolved_path.name
if clear_db:
    self._store.clear_repo(repo_name)
self._store.create_indexes()
import_start = time.time()
import_result = self._store.import_graph(graph, repo_name=repo_name)
```

Then after `import_result = ...`, set the active repo:
```python
self._current_repo = repo_name
```

- [ ] **Step 10: Run tests**

```
pytest tests/test_mcp_multirepo.py tests/test_neo4j_mock.py -v
```

Expected: all pass.

- [ ] **Step 11: Commit**

```bash
git add archgraph/mcp/server.py tests/test_mcp_multirepo.py
git commit -m "feat: add _current_repo state, use_repo tool, and repos active field to MCP server"
```

---

## Task 4: Auto-filter in all tool handlers

**Files:**
- Modify: `archgraph/mcp/server.py`
- Modify: `archgraph/tool/impact.py`
- Test: `tests/test_mcp_multirepo.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_mcp_multirepo.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_mcp_multirepo.py::TestAutoRepoFilter -v
```

Expected: `FAILED` — filters not yet implemented.

- [ ] **Step 3: Add `_require_repo` helper to `ArchGraphMCP`**

Add this method just before `_handle_extract_sync`:

```python
def _require_repo(self) -> str:
    """Return the active repo name or raise ValueError."""
    if self._current_repo is None:
        raise ValueError("No active repo. Call use_repo first.")
    return self._current_repo
```

- [ ] **Step 4: Filter `query` and `cypher` handlers**

In `handle_tool_call`, replace the `query`/`cypher` block:

Old:
```python
if name == "query" or name == "cypher":
    cypher = arguments.get("cypher") or arguments.get("query", "")
    params = arguments.get("params", {})
    result = self._store.query(cypher, params)
```

New:
```python
if name == "query" or name == "cypher":
    repo = self._require_repo()
    cypher = arguments.get("cypher") or arguments.get("query", "")
    params = dict(arguments.get("params") or {})
    params["_repo"] = repo
    result = self._store.query(cypher, params)
```

- [ ] **Step 5: Filter `stats` handler**

In `handle_tool_call`, replace:
```python
elif name == "stats":
    result = self._get_stats()
```
With:
```python
elif name == "stats":
    repo = self._require_repo()
    result = self._get_stats(repo)
```

Update `_get_stats` signature and queries:

```python
def _get_stats(self, repo: str) -> dict[str, Any]:
    """Get graph statistics for the active repo."""
    db_stats = self._store.stats(repo=repo)

    cluster_count = self._store.query(
        "MATCH (c:Cluster {repo: $repo}) RETURN count(c) AS count", {"repo": repo}
    )
    process_count = self._store.query(
        "MATCH (p:Process {repo: $repo}) RETURN count(p) AS count", {"repo": repo}
    )

    return {
        "graph_stats": db_stats,
        "clusters": cluster_count[0]["count"] if cluster_count else 0,
        "processes": process_count[0]["count"] if process_count else 0,
    }
```

- [ ] **Step 6: Filter `source` handler**

In `handle_tool_call`, replace:
```python
elif name == "source":
    symbol_id = arguments["symbol_id"]
    source_result = self._store.get_source(symbol_id)
    if source_result:
        result = source_result
    else:
        result = {"error": f"Symbol not found or has no body: {symbol_id}"}
```
With:
```python
elif name == "source":
    repo = self._require_repo()
    symbol_id = arguments["symbol_id"]
    source_result = self._store.get_source(symbol_id, repo=repo)
    if source_result:
        result = source_result
    else:
        result = {"error": f"Symbol not found or has no body: {symbol_id}"}
```

- [ ] **Step 7: Filter `context` handler**

In `handle_tool_call`, replace:
```python
elif name == "context":
    result = self._get_context(arguments["symbol_id"])
```
With:
```python
elif name == "context":
    repo = self._require_repo()
    result = self._get_context(arguments["symbol_id"], repo=repo)
```

Update `_get_context` signature to `_get_context(self, symbol_id: str, repo: str)` and add `AND n.repo = $repo` to the main symbol lookup:

```python
symbol = self._store.query(
    "MATCH (n:_Node {_id: $id}) WHERE n.repo = $repo RETURN properties(n) AS props",
    {"id": symbol_id, "repo": repo},
)
if not symbol:
    return {"error": f"Symbol not found in repo {repo!r}: {symbol_id}"}
```

The callers/callees queries don't need repo filter — they start from the validated node.

- [ ] **Step 8: Filter `impact` handler**

In `handle_tool_call`, replace:
```python
elif name == "impact":
    symbol_id = arguments["symbol_id"]
    direction = arguments.get("direction", "upstream")
    max_depth = arguments.get("max_depth", 5)
    result = self._impact.analyze_impact(symbol_id, direction, max_depth)
```
With:
```python
elif name == "impact":
    repo = self._require_repo()
    symbol_id = arguments["symbol_id"]
    check = self._store.query(
        "MATCH (n:_Node {_id: $id, repo: $repo}) RETURN n._id LIMIT 1",
        {"id": symbol_id, "repo": repo},
    )
    if not check:
        result = {"error": f"Symbol {symbol_id!r} not found in repo {repo!r}"}
    else:
        direction = arguments.get("direction", "upstream")
        max_depth = arguments.get("max_depth", 5)
        result = self._impact.analyze_impact(symbol_id, direction, max_depth)
```

- [ ] **Step 9: Filter `detect_changes` handler**

In `handle_tool_call`, replace:
```python
elif name == "detect_changes":
    result = self._impact.analyze_change_impact(arguments["changed_files"])
```
With:
```python
elif name == "detect_changes":
    repo = self._require_repo()
    result = self._impact.analyze_change_impact(arguments["changed_files"], repo_name=repo)
```

Update `ImpactAnalyzer.analyze_change_impact` in `archgraph/tool/impact.py` to accept and use `repo_name`:

```python
def analyze_change_impact(
    self, changed_files: list[str], repo_name: str | None = None
) -> dict[str, Any]:
    """Analyze impact of file changes."""
    assert self._store is not None

    repo_clause = " AND f.repo = $repo" if repo_name else ""
    params_base: dict[str, Any] = {"files": changed_files}
    if repo_name:
        params_base["repo"] = repo_name

    changed_funcs = self._store.query(
        f"MATCH (f:Function) WHERE f.file IN $files{repo_clause} "
        "RETURN f._id AS id, f.name AS name, f.file AS file, "
        "f.is_input_source AS is_input, f.is_dangerous_sink AS is_sink",
        params_base,
    )

    affected_clusters = self._store.query(
        f"MATCH (f:Function)-[:BELONGS_TO]->(c:Cluster) "
        f"WHERE f.file IN $files{repo_clause} "
        "RETURN DISTINCT c._id AS id, c.name AS name, c.cohesion AS cohesion",
        params_base,
    )

    affected_processes = self._store.query(
        f"MATCH (f:Function)-[:PARTICIPATES_IN]->(p:Process) "
        f"WHERE f.file IN $files{repo_clause} "
        "RETURN DISTINCT p._id AS id, p.name AS name, p.type AS type",
        params_base,
    )

    security_cypher = (
        f"MATCH (f:Function)-[:CALLS*1..3]->(sink:Function {{is_dangerous_sink: true}}) "
        f"WHERE f.file IN $files{repo_clause} "
        "RETURN DISTINCT sink._id AS id, sink.name AS sink_name"
    )
    security_risks = self._store.query(security_cypher, params_base)

    risk_level = self._assess_risk(changed_funcs, security_risks)

    return {
        "changed_files": changed_files,
        "changed_functions": changed_funcs,
        "affected_clusters": affected_clusters,
        "affected_processes": affected_processes,
        "security_risks": security_risks,
        "risk_level": risk_level,
    }
```

- [ ] **Step 10: Filter `search` handler**

In `_handle_search`, replace:
```python
conditions = ["n._id IS NOT NULL"]
params: dict[str, Any] = {}
```
With:
```python
repo = self._require_repo()
conditions = ["n._id IS NOT NULL", "n.repo = $repo"]
params: dict[str, Any] = {"repo": repo}
```

- [ ] **Step 11: Filter `search_calls` handler**

In `_handle_search_calls`, add `_require_repo()` once at the very top of the method, before the depth branch:

```python
def _handle_search_calls(self, arguments: dict[str, Any]) -> list[dict[str, Any]]:
    """Handle search_calls tool — find call relationships."""
    repo = self._require_repo()          # ← add this
    caller = arguments.get("caller", "")
    ...
```

For the depth=1 path, replace:
```python
conditions = []
params = {"limit": limit}
```
With:
```python
conditions = ["f.repo = $repo", "t.repo = $repo"]
params: dict[str, Any] = {"repo": repo, "limit": limit}
```

For the depth>1 path, after existing `conditions = []` and `params` dict initialisation, append:
```python
conditions.append("src.repo = $repo")
conditions.append("dst.repo = $repo")
params["repo"] = repo
```

- [ ] **Step 12: Filter `find_vulnerabilities` handler**

In `_find_vulnerabilities`, add `_require_repo()` at the top of the method and use `$repo` in the query:

```python
def _find_vulnerabilities(self, severity: str | None = None) -> list[dict[str, Any]]:
    """Find vulnerabilities with optional severity filter."""
    repo = self._require_repo()
    cypher = (
        "MATCH (d:Dependency {repo: $repo})-[:AFFECTED_BY]->(v:Vulnerability) "
        "RETURN d.name AS dependency, d.version AS version, "
        "v.vuln_id AS vuln_id, v.summary AS summary, v.severity AS severity"
    )
    results = self._store.query(cypher, {"repo": repo})
    if severity:
        results = [r for r in results if severity.upper() in (r.get("severity") or "").upper()]
    return results
```

No change needed in `handle_tool_call` — the call site `self._find_vulnerabilities(severity)` stays the same.

- [ ] **Step 13: Run all tests**

```
pytest tests/ -v --tb=short -q
```

Expected: 212+ passed, 22 skipped, 0 failed.

- [ ] **Step 14: Commit**

```bash
git add archgraph/mcp/server.py archgraph/tool/impact.py tests/test_mcp_multirepo.py
git commit -m "feat: enforce active repo in all MCP tool handlers with auto-filter"
```

---

## Quick Verification Checklist

After all tasks complete, verify end-to-end with the MCP tools:

- [ ] Call `use_repo("fastify")` → returns `{"active_repo": "fastify", ...}`
- [ ] Call `search(name="route")` → returns fastify-only results
- [ ] Call `search(name="route")` without `use_repo` first → returns `{"error": "No active repo..."}`
- [ ] Call `repos()` → fastify entry has `"active": true`
- [ ] Call `query(cypher="MATCH (n:_Node {repo: $_repo}) RETURN count(n) AS c")` → returns fastify count
- [ ] Call `extract(repo="/tmp/go-test")` → active repo auto-switches to `go-test`
- [ ] Old data from other repos still in Neo4j (not wiped)
