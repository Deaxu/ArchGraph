# MCP Server Reference

ArchGraph MCP (Model Context Protocol) server — 13 tools, 4 resources.

## Starting the Server

```bash
archgraph mcp [--neo4j-uri URI] [--neo4j-user USER] [--neo4j-password PASS] [--neo4j-database DB]
```

### Connecting Agents

**Claude Code:**
```bash
claude mcp add archgraph -- archgraph mcp
```

**Cursor** (`~/.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "archgraph": {
      "command": "archgraph",
      "args": ["mcp"]
    }
  }
}
```

**OpenCode** (`~/.config/opencode/config.json`):
```json
{
  "mcp": {
    "archgraph": {
      "command": "archgraph",
      "args": ["mcp"]
    }
  }
}
```

---

## Multi-Repo Workflow

When multiple repos are indexed, call `use_repo` before any query tool:

```
1. repos        → list indexed repos
2. use_repo     → select active repo
3. search/query/impact/...  → work with selected repo
```

When only one repo is indexed, `use_repo` is optional.

---

## Tools

### `extract`

Extract code graph from a repository.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `repo` | string | **yes** | — | Git URL or local path |
| `languages` | string | no | `"auto"` | Comma-separated or `"auto"` |
| `clear_db` | boolean | no | `false` | Clear graph before import |
| `include_deep` | boolean | no | `true` | CFG, data flow, taint analysis |
| `include_cve` | boolean | no | `false` | CVE scanning via OSV API |
| `include_clustering` | boolean | no | `false` | Community detection |
| `include_process` | boolean | no | `false` | Execution flow tracing |
| `include_scip` | boolean | no | `true` | SCIP compiler-backed call resolution |
| `include_git` | boolean | no | `true` | Git history extraction |
| `include_deps` | boolean | no | `true` | Dependency extraction |
| `include_clang` | boolean | no | `true` | libclang C/C++ analysis |
| `include_body` | boolean | no | `true` | Store source code in nodes |
| `include_annotations` | boolean | no | `true` | TODO/HACK/FIXME scanning |
| `workers` | integer | no | `0` | Threads (0=auto, 1=sequential) |
| `incremental` | boolean | no | `false` | Only re-extract changed files |
| `max_body_size` | integer | no | `51200` | Max body bytes per node |
| `branch` | string | no | — | Branch to clone (git URLs) |
| `depth` | integer | no | `1` | Clone depth (git URLs) |

```json
{
  "name": "extract",
  "arguments": {
    "repo": "https://github.com/user/project",
    "languages": "auto",
    "clear_db": true
  }
}
```

---

### `query`

Execute a Cypher query against the code knowledge graph.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cypher` | string | **yes** | Cypher query string |
| `params` | object | no | Query parameters |

```json
{
  "name": "query",
  "arguments": {
    "cypher": "MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file LIMIT 10"
  }
}
```

---

### `cypher`

Alias for `query`. Uses `query` parameter instead of `cypher`.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | **yes** | Cypher query string |
| `params` | object | no | Query parameters |

---

### `search`

Search symbols by name, type, or file pattern.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | no | Symbol name (`*` wildcards supported) |
| `type` | enum | no | `function`, `class`, `struct`, `interface`, `enum`, `module`, `file` |
| `file_pattern` | string | no | File path pattern (`*` wildcards) |
| `limit` | integer | no | Max results (default: 20) |

```json
{
  "name": "search",
  "arguments": {
    "name": "getSystemPrompt",
    "type": "function",
    "file_pattern": "*prompts*"
  }
}
```

---

### `search_calls`

Search call relationships between functions. Supports transitive call chains.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `caller` | string | no | Caller name (partial match) |
| `target` | string | no | Target name (partial match) |
| `file` | string | no | File path filter (partial match) |
| `resolved_only` | boolean | no | Only resolved calls (default: false) |
| `source` | enum | no | `scip` (compiler), `heuristic` (name-based), `any` (default) |
| `max_depth` | integer | no | Call chain depth (default: 1) |
| `limit` | integer | no | Max results (default: 20) |

```json
{
  "name": "search_calls",
  "arguments": {
    "target": "getSystemPrompt",
    "resolved_only": true,
    "max_depth": 3
  }
}
```

---

### `source`

Get source code of a symbol.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `symbol_id` | string | **yes** | Symbol node ID (e.g. `func:src/auth.c:validate:42`) |

Returns `body`, `name`, `file`, `line_start`, `line_end`, `body_lines`, `body_truncated`.

---

### `context`

Get 360-degree view of a symbol: properties, callers, callees, cluster, security labels.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `symbol_id` | string | **yes** | Symbol node ID |

---

### `impact`

Analyze blast radius of a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `symbol_id` | string | **yes** | — | Function node ID |
| `direction` | enum | no | `"downstream"` | `upstream` (callers), `downstream` (callees), `both` |
| `max_depth` | integer | no | `5` | Max traversal depth |

Returns: affected functions, transitive impact, security flags, confidence score.

```json
{
  "name": "impact",
  "arguments": {
    "symbol_id": "func:src/auth.c:validate:42",
    "direction": "upstream",
    "max_depth": 5
  }
}
```

---

### `detect_changes`

Analyze impact of changed files on the codebase.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `changed_files` | string[] | **yes** | List of changed file paths |

Returns affected clusters, processes, security risks, risk level.

---

### `find_vulnerabilities`

Find known CVE vulnerabilities in project dependencies.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `severity` | string | no | Filter: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |

---

### `stats`

Get graph statistics: node/edge counts, clusters, processes.

No parameters.

---

### `repos`

List all extracted and indexed repositories.

No parameters.

---

### `use_repo`

Set the active repository for subsequent queries. Required when multiple repos are indexed.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | **yes** | Repository name (as shown by `repos`) |

Must be called before: `search`, `context`, `impact`, `source`, `stats`, `detect_changes`, `query`, `cypher`, `search_calls`, `find_vulnerabilities`.

```json
{
  "name": "use_repo",
  "arguments": {
    "name": "fastify"
  }
}
```

---

## Resources

Resources provide instant context without tool calls:

| URI | Description |
|-----|-------------|
| `archgraph://schema` | Node labels, edge types, property keys |
| `archgraph://security` | Input sources, dangerous sinks, taint paths, vulnerabilities |
| `archgraph://clusters` | Detected functional clusters with cohesion scores |
| `archgraph://processes` | Traced execution flows from entry points |

---

## Caching

Tool results are cached with a **60-second TTL** (max 128 entries). Identical tool calls within the TTL window return cached results instantly. Cache keys are computed from tool name + JSON-serialized arguments (MD5).
