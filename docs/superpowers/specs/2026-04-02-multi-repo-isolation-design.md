# Multi-Repo Isolation Design

**Date:** 2026-04-02  
**Status:** Approved

## Problem

All extracted repos share a single Neo4j database with no per-repo isolation. Node ownership is unknown — you can't tell which node belongs to which repo. The registry (`~/.archgraph/registry.json`) is just metadata and drifts out of sync with Neo4j. Running `extract` with `clear_db=True` (the default) wipes every repo's data, not just the target.

## Decisions

| Question | Decision |
|----------|----------|
| No active repo set → tool behavior | Error: `"No active repo. Call use_repo first."` |
| How to select active repo | New `use_repo` tool (separate, not extending `repos`) |
| `query`/`cypher` filtering | Same error when no active repo; `$_repo` auto-injected when set |
| After `extract` completes | Active repo automatically switches to the newly extracted repo |

## Architecture

### 1. `repo` Property on Nodes

Every node written to Neo4j gets a `repo` property equal to the repo's directory name (e.g. `"fastify"`).

Injection point: `Neo4jStore.import_graph(graph, repo_name)` — added as a new required parameter. The `repo_name` is injected into each node's property dict before the batch write. The in-memory `GraphData` object is not modified.

```python
props["repo"] = repo_name
```

Index added to `_INDEXES`:
```python
("_Node", ["repo"])
```

### 2. Per-Repo Clear

`Neo4jStore.clear()` is replaced by `Neo4jStore.clear_repo(repo_name)`:

```cypher
MATCH (n:_Node {repo: $repo}) DETACH DELETE n
```

`extract` with `clear_db=True` now clears only the target repo, not all repos. The global `clear()` is kept for explicit full wipes.

### 3. `ArchGraphMCP` State

```python
self._current_repo: str | None = None
```

Set by `use_repo` and automatically by `extract` on success.

**Cache key** includes `_current_repo` so cached results are invalidated when the active repo changes.

### 4. New `use_repo` Tool

```json
{
  "name": "use_repo",
  "description": "Set the active repository for all subsequent queries",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": { "type": "string", "description": "Repository name (e.g. 'fastify')" }
    },
    "required": ["name"]
  }
}
```

Validates the name exists in the registry. Returns:
```json
{"active_repo": "fastify", "node_count": 2825, "edge_count": 18487}
```

### 5. Tool Behavior Matrix

| Tool | No active repo | Active repo set |
|------|---------------|-----------------|
| `search` | Error | `WHERE n.repo = $repo` injected |
| `context` | Error | `MATCH (n:_Node {_id: $id, repo: $repo})` — validates ownership |
| `impact` | Error | Traversal starts from node validated to belong to repo |
| `source` | Error | `get_source` lookup adds `AND n.repo = $repo` check |
| `stats` | Error | All counts filtered `WHERE n.repo = $repo` |
| `detect_changes` | Error | File MATCH queries add `AND f.repo = $repo` |
| `query` / `cypher` | Error | `$_repo` auto-injected as param |
| `repos` | Works | Works, adds `"active": true/false` |
| `use_repo` | Works | Works, switches active repo |
| `extract` | Works, sets active repo | Works, switches active repo |

### 6. `query` / `cypher` Filtering

Auto-inject `_repo` into the params dict before executing:

```python
params["_repo"] = self._current_repo
```

The LLM uses `$_repo` in WHERE clauses:
```cypher
MATCH (n:Function {repo: $_repo}) WHERE n.name = 'parse' RETURN n
```

Tool descriptions are updated to document `$_repo`.

### 7. `repos` Tool Update

Each entry gains an `active` boolean field:
```json
{"name": "fastify", "active": true, "node_count": 2825, ...}
```

## Files to Change

| File | Change |
|------|--------|
| `archgraph/graph/neo4j_store.py` | `import_graph` gets `repo_name` param, inject `repo` property; add `clear_repo()`; add `repo` index |
| `archgraph/mcp/server.py` | `_current_repo` state; `use_repo` tool + handler; auto-filter in all tool handlers; cache key fix; `extract` sets active repo; `repos` adds `active` field |
| `archgraph/cli.py` | Pass `repo_name` to `import_graph` |
| `archgraph/api.py` | Pass `repo_name` to `import_graph` |

## Out of Scope

- Per-repo Neo4j databases (requires Enterprise Edition)
- Cross-repo queries (no active repo = error, not global search)
- Registry cleanup / sync validation
