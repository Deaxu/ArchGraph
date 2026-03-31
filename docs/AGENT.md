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

## Python API (Direct Integration)

For custom agent frameworks:

```python
from archgraph.graph.neo4j_store import Neo4jStore
from archgraph.tool.impact import ImpactAnalyzer
from archgraph.search import HybridSearcher
from archgraph.skills import SkillGenerator

# Connect
store = Neo4jStore("bolt://localhost:7687")
store.connect()

# Impact analysis
impact = ImpactAnalyzer(store)
result = impact.analyze_impact("func:src/auth.c:validate:42", direction="both")

# Hybrid search
searcher = HybridSearcher(store)
searcher.build_index()
results = searcher.search("authentication bypass", top_k=10)

# Generate skills
generator = SkillGenerator(store)
skill_files = generator.generate_skills(Path("/path/to/repo"))

store.close()
```

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
