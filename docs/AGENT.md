# AI Agent Integration

ArchGraph integrates with **any MCP-compatible AI agent** — Cursor, Claude Code, Windsurf, OpenCode, and more.

## MCP Server

The MCP (Model Context Protocol) server exposes ArchGraph's knowledge graph to AI agents through a standardized interface.

### Prerequisites

Neo4j must be running before starting the MCP server:

```bash
docker compose up -d neo4j           # password: archgraph
```

### Starting the Server

```bash
# Start MCP server (stdio transport)
archgraph mcp

# Or with custom Neo4j connection
archgraph mcp --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-password mypass
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

## MCP Tools

### `query`

Execute Cypher queries against the code knowledge graph.

```json
{
  "name": "query",
  "arguments": {
    "cypher": "MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file LIMIT 10"
  }
}
```

### `impact`

Analyze blast radius of a function — what it affects or what affects it.

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

Returns:
```json
{
  "symbol": "func:src/auth.c:validate:42",
  "immediate": [{"id": "...", "name": "handle_login", "file": "src/api.c"}],
  "downstream": [...],
  "transitive": [...],
  "total_affected": 15,
  "confidence": 0.85,
  "security_flags": ["input_source:func:src/net.c:recv_data:10"]
}
```

### `context`

Get 360° view of a symbol.

```json
{
  "name": "context",
  "arguments": {
    "symbol_id": "func:src/auth.c:validate:42"
  }
}
```

Returns callers, callees, cluster membership, process participation, and security labels.

### `detect_changes`

Analyze impact of changed files.

```json
{
  "name": "detect_changes",
  "arguments": {
    "changed_files": ["src/api.c", "src/auth.c"]
  }
}
```

Returns affected clusters, processes, security risks, and risk level assessment.

### `find_vulnerabilities`

Find CVE vulnerabilities in project dependencies.

```json
{
  "name": "find_vulnerabilities",
  "arguments": {
    "severity": "CRITICAL"
  }
}
```

### `source`

Get source code of a function, class, struct, or other symbol.

```json
{
  "name": "source",
  "arguments": {
    "symbol_id": "func:src/constants/prompts.ts:getSystemPrompt:443"
  }
}
```

Returns body, name, file, line range, body_lines, body_truncated.

### `extract`

Extract code graph from a repository. Auto-detects languages, runs SCIP compiler-backed indexers, imports to Neo4j.

```json
{
  "name": "extract",
  "arguments": {
    "repo": "https://github.com/oboard/claude-code-rev",
    "languages": "auto",
    "clear_db": true
  }
}
```

Returns node/edge counts, extraction time, SCIP resolution stats.

### `search`

Search for symbols by name, type, or file pattern. No Cypher needed.

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

### `search_calls`

Find call relationships between functions. Supports transitive call chains.

```json
{
  "name": "search_calls",
  "arguments": {
    "target": "getSystemPrompt",
    "resolved_only": true,
    "max_depth": 3,
    "limit": 10
  }
}
```

### `repos`

List all extracted and indexed repositories.

```json
{
  "name": "repos",
  "arguments": {}
}
```

### `cypher` / `stats`

- `cypher`: Raw Cypher query (alias for `query`)
- `stats`: Graph statistics (node/edge counts, clusters, processes)

---

## MCP Resources

Resources provide instant context without tool calls:

| Resource | Description |
|----------|-------------|
| `archgraph://schema` | Node labels, edge types, property keys |
| `archgraph://security` | Input sources, dangerous sinks, taint paths, vulnerabilities |
| `archgraph://clusters` | Detected functional clusters with cohesion scores |
| `archgraph://processes` | Traced execution flows from entry points |

---

## Agent Skills

ArchGraph generates security-focused skill files that help AI agents understand the codebase:

```bash
archgraph skills /path/to/repo
```

Generated files (in `.archgraph/skills/`):

| File | Content |
|------|---------|
| `OVERVIEW.md` | Graph statistics, most-called functions, query templates |
| `SECURITY.md` | Input sources, dangerous sinks, taint paths, CVEs |
| `IMPACT.md` | Impact analysis guidelines, risk assessment matrix |
| `CLUSTER_*.md` | Per-cluster files with member functions and guidelines |

---

## Web Dashboard

Interactive graph exploration with search, security overview, and node details:

```bash
archgraph serve --port 8080
# Open http://localhost:8080
```

Features:
- **Hybrid search** — Find functions, classes, files
- **Security tab** — Input sources, dangerous sinks, taint paths
- **Clusters tab** — Functional group visualization
- **Node details** — Properties, callers, callees

---

## Example Agent Workflows

### Security Audit

```
User: "Are there any input-to-sink paths without validation?"

Agent:
1. Read resource: archgraph://security
2. For each taint path, use context tool to get full details
3. Report: "Found 3 unvalidated paths:
   - net_recv() → memcpy() in src/net/handler.c
   - read_packet() → strcpy() in src/net/parser.c  
   - fetch_url() → system() in src/util/downloader.c
   All paths need input validation before reaching sinks."
```

### Change Impact Analysis

```
User: "I'm modifying the validate() function in auth.c. What could break?"

Agent:
1. Use impact tool: symbol_id="func:src/auth.c:validate:X", direction="upstream"
2. Use detect_changes with the file
3. Report: "Changing validate() affects:
   - 8 immediate callers (API handlers, middleware)
   - 2 clusters (auth_cluster, api_cluster)
   - 1 process (login_flow)
   Risk level: HIGH — function is security-critical"
```

### Dependency Security

```
User: "Check if our dependencies have any known vulnerabilities"

Agent:
1. Use find_vulnerabilities tool
2. For each CVE, use context to find which modules depend on it
3. Report: "Found 2 vulnerabilities:
   - CVE-2024-1234 in openssl@3.0.1 (CRITICAL) — affects auth module
   - CVE-2024-5678 in libxml2@2.9.0 (HIGH) — affects parser module
   Recommend upgrading both immediately."
```

### Architecture Exploration

```
User: "What are the main functional areas of this codebase?"

Agent:
1. Read resource: archgraph://clusters
2. For each cluster, use context on representative functions
3. Report: "This codebase has 5 main modules:
   - auth_cluster (12 functions, cohesion: 0.89) — Authentication & authorization
   - db_cluster (8 functions, cohesion: 0.92) — Database operations
   - api_cluster (15 functions, cohesion: 0.76) — REST API handlers
   - net_cluster (10 functions, cohesion: 0.81) — Network I/O
   - util_cluster (6 functions, cohesion: 0.45) — Utilities"
```

---

## Python API

High-level API for programmatic access:

```python
from archgraph import ArchGraph

with ArchGraph() as ag:
    # Extract a repo (clone + detect languages + SCIP + Neo4j import)
    result = ag.extract("https://github.com/oboard/claude-code-rev")
    print(f"{result['nodes']} nodes, {result['edges']} edges")

    # Search symbols
    funcs = ag.search(name="getSystemPrompt", type="function")

    # Search call chains
    calls = ag.search_calls(target="getSystemPrompt", resolved_only=True)

    # Get source code
    source = ag.source(funcs[0]["id"])

    # 360° context
    ctx = ag.context(funcs[0]["id"])

    # Blast radius
    impact = ag.impact(funcs[0]["id"], direction="downstream", max_depth=5)

    # Graph stats
    stats = ag.stats()

    # Raw Cypher
    results = ag.query("MATCH (f:Function) RETURN f.name LIMIT 5")

    # Vulnerability scan
    vulns = ag.find_vulnerabilities(severity="CRITICAL")

    # Change impact
    changes = ag.detect_changes(["src/auth.ts", "src/api.ts"])

    # List repos
    repos = ag.repos()
```

All 12 tools available: `extract`, `search`, `repos`, `search_calls`, `query`, `cypher`, `source`, `context`, `stats`, `impact`, `detect_changes`, `find_vulnerabilities`.

---

## Multi-Repo Support

ArchGraph maintains a global registry of indexed repositories:

```bash
# List all indexed repos
archgraph repos

# Output format
archgraph repos --format json
```

The MCP server can serve all indexed repos. When only one repo is indexed, the tool's `repo` parameter is optional.
