<p align="center">
  <img src="assets/banner.svg" alt="ArchGraph" width="700"/>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"/></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Server-green.svg" alt="MCP Server"/></a>
</p>

<p align="center">
  <b>Security-first code intelligence for AI agents.</b><br/>
  Parses <b>10 languages</b>, builds a knowledge graph with <b>taint analysis</b>, <b>CVE detection</b>, <b>clustering</b>, and <b>process tracing</b>.<br/>
  Connect to any AI agent via <b>MCP</b> — Cursor, Claude Code, Windsurf, and more.
</p>

---

## Why ArchGraph?

**Other tools help you *understand* code. ArchGraph helps you *secure* it.**

ArchGraph builds a Neo4j knowledge graph of your codebase with security-aware analysis that other tools miss:

| | **ArchGraph** | **Generic Code Search** | **Basic AST Parsers** |
|--|---------------|------------------------|----------------------|
| **Taint Analysis** | ✅ Input → Sink tracking | ❌ | ❌ |
| **CVE Detection** | ✅ Automatic via OSV API | ❌ | ❌ |
| **CFG / Data Flow** | ✅ via libclang + tree-sitter | ❌ | Partial |
| **Security Labels** | ✅ Auto-detection | ❌ | ❌ |
| **Community Clustering** | ✅ Functional groups | ❌ | ❌ |
| **Process Tracing** | ✅ Execution flows | ❌ | ❌ |
| **MCP Integration** | ✅ 7 tools for AI agents | ❌ | ❌ |
| **Graph Diff** | ✅ Snapshot comparison | ❌ | ❌ |

---

## 🤖 AI Agent Integration (MCP)

ArchGraph works with **any MCP-compatible AI agent** — Cursor, Claude Code, Windsurf, OpenCode, and more.

### Quick Setup

```bash
# Install
pip install archgraph

# Index your repo
archgraph extract . -l c,cpp,rust -w 4 --include-cve --include-clustering

# Start MCP server
archgraph mcp
```

### Connect Your Agent

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

### What Your Agent Gets

**7 MCP Tools:**

| Tool | What It Does |
|------|-------------|
| `query` | Execute Cypher queries against the code graph |
| `impact` | Blast radius analysis — what's affected by a change |
| `context` | 360° symbol view — callers, callees, cluster, security labels |
| `detect_changes` | Git-diff impact — maps changed files to affected processes |
| `find_vulnerabilities` | Find CVE vulnerabilities in dependencies |
| `cypher` | Raw Cypher graph queries |
| `stats` | Graph statistics and health |

**4 MCP Resources:**

| Resource | Purpose |
|----------|---------|
| `archgraph://schema` | Graph schema for writing Cypher queries |
| `archgraph://security` | Input sources, dangerous sinks, taint paths |
| `archgraph://clusters` | Functional clusters with cohesion scores |
| `archgraph://processes` | Execution flows from entry points |

### Example: Agent Finds a Vulnerability

```
You: "Are there any buffer overflow risks in the network code?"

Agent (using ArchGraph MCP):
1. Queries: MATCH (f:Function {is_input_source: true}) WHERE f.file CONTAINS "net"
2. Traces: MATCH path = (src)-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true})
3. Reports: "Found 2 taint paths:
   - net_recv() → memcpy() in src/net/handler.c (depth: 3)
   - read_packet() → strcpy() in src/net/parser.c (depth: 4)
   Both paths reach dangerous sinks without validation."
```

---

## 🔒 Security Analysis

### Automatic Security Labeling

Every function is automatically labeled:

```cypher
MATCH (f:Function {is_input_source: true, is_dangerous_sink: true})
RETURN f.name, f.file
-- ⚠️ These functions read input AND use dangerous operations
```

Labels applied:
- `is_input_source` — reads external data (recv, read, fetch, getParameter, ...)
- `is_dangerous_sink` — dangerous operations (memcpy, exec, eval, innerHTML, ...)
- `is_allocator` — memory operations (malloc, new, alloc, ...)
- `is_crypto` — cryptographic functions
- `is_parser` — parsing/decoding operations

### Taint Path Detection

```cypher
MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..8]->(sink:Function {is_dangerous_sink: true})
RETURN src.name AS entry, sink.name AS risk, length(path) AS depth
```

### CVE Enrichment

```bash
archgraph extract . --include-cve
```

Automatically queries [OSV](https://osv.dev) for known vulnerabilities in your dependencies.

---

## 🔍 Use Cases

### For Security Auditors
```bash
# Full security analysis
archgraph extract /target/repo -l c,cpp --include-cve --include-clang

# Find all input-to-sink paths
archgraph query "MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true}) RETURN src.name, sink.name"
```

### For Developers (with AI Agent)
```bash
# Index with all features
archgraph extract . --include-cve --include-clustering --include-process

# Let your AI agent explore
archgraph mcp
# Now ask: "What does the auth module do?" or "What breaks if I change validate()?"
```

### For Code Review
```bash
# See what changed and what's affected
archgraph diff /path/to/repo

# Impact analysis before merging
archgraph impact "func:src/api.c:handle_request:42" --direction both
```

### For Reverse Engineering
```bash
# Extract from compiled project
archgraph extract /path/to/repo -l c,cpp,rust --include-clang --include-deep

# Explore the graph
archgraph query "MATCH (f:Function) WHERE f.is_exported = true RETURN f.name, f.file ORDER BY f.name"
```

---

## Highlights

- **10 languages** — C, C++, Rust, Java, Go, JavaScript, TypeScript, Kotlin, Swift, Objective-C
- **Auto-detect** — Automatically detects languages from file extensions
- **Deep analysis** — CFG, data flow, taint tracking via libclang (C/C++) and tree-sitter
- **Security auditing** — Input/sink detection, risk scores (0-100), CVE enrichment
- **AI Agent ready** — MCP server with 7 tools and 4 resources for any agent framework
- **Clustering** — Functional community detection with cohesion scores
- **Process tracing** — Execution flow analysis from entry points
- **Hybrid search** — BM25 + graph relevance for semantic code search
- **Web dashboard** — Interactive graph exploration at `http://localhost:8080`
- **Git integration** — Commit history, change stats, security fix detection
- **Graph diff** — Compare repo state against stored graph
- **Export formats** — JSON, GraphML, CSV for external tools
- **HTML reports** — Single-file security reports, shareable without Neo4j
- **Incremental extraction** — Only re-extract changed files
- **Parallel pipeline** — Multi-threaded extraction with 11 steps
- **Multi-repo registry** — Manage multiple indexed repositories

---

## Installation

```bash
pip install archgraph

# With all optional extras (clang, kotlin, swift, objc)
pip install archgraph[all]

# Development
pip install archgraph[dev]
```

**Requirements:** Python 3.11+, Neo4j 5.x (for graph storage)

> **Docker:** Run `docker compose up -d neo4j` to start Neo4j with password `archgraph`.

---

## Quick Start

```bash
# Basic extraction (auto-detects languages)
archgraph extract /path/to/repo -w 4

# From GitHub URL
archgraph extract https://github.com/madler/zlib --clear-db

# Full analysis with security features
archgraph extract /path/to/repo --include-cve --include-clustering --include-process

# Run Cypher query
archgraph query "MATCH (f:Function {is_input_source: true}) RETURN f.name LIMIT 10"

# Start web dashboard
archgraph serve --port 8080

# Start MCP server for AI agents
archgraph mcp

# Generate agent skills
archgraph skills /path/to/repo

# Impact analysis
archgraph impact "func:src/main.c:main:1" --direction both --depth 5

# Export graph (JSON, GraphML, or CSV)
archgraph export /path/to/repo --format json
archgraph export /path/to/repo --format graphml -o graph.graphml

# Generate HTML security report
archgraph report /path/to/repo

# List indexed repos
archgraph repos
```

---

## Docker

```bash
# Start Neo4j
docker compose up -d neo4j

# Extract (mount your repo)
docker compose run archgraph extract /data/repo -l c,cpp,rust -w 4

# With all features
docker compose run archgraph extract /data/repo -l c,cpp --include-cve --include-clustering

# Query
docker compose run archgraph query "MATCH (f:Function) RETURN f.name LIMIT 10"

# MCP server
docker compose run archgraph mcp

# Build with optional extras
docker build --build-arg INSTALL_EXTRAS=all -t archgraph .
```

---

## Python API

```python
from pathlib import Path
from archgraph.config import ExtractConfig
from archgraph.graph.builder import GraphBuilder

config = ExtractConfig(
    repo_path=Path("/path/to/repo"),
    languages=["c", "cpp", "rust"],
    workers=4,
    include_cve=True,
    include_clustering=True,
    include_process=True,
)
graph = GraphBuilder(config).build()

print(f"Nodes: {graph.node_count}, Edges: {graph.edge_count}")
print(graph.stats())
```

### MCP Server (Python)

```python
import asyncio
from archgraph.mcp.server import run_mcp_server

asyncio.run(run_mcp_server(
    neo4j_uri="bolt://localhost:7687",
    neo4j_user="neo4j",
    neo4j_password="neo4j",
))
```

---

## Architecture

```
                  ┌──────────────────────────────────────────────────┐
                  │         GraphBuilder Pipeline (11 steps)         │
                  │                                                  │
  Local Path ─────┤  1. Tree-sitter structural extraction            │
     or           │  2. Git history                                  │
  GitHub URL ─────┤  3. Dependency extraction                        │──── Neo4j
  (auto clone)    │  4. Annotation scanning                          │     Store
                  │  5. Security labeling                            │       │
                  │  6. Clang deep analysis (C/C++)                  │       ├── MCP Server
                  │  7. Tree-sitter deep analysis (Rust/Java/Go/…)   │       ├── Web Dashboard
                  │  8. Churn enrichment                             │       └── Hybrid Search
                  │  9. CVE enrichment (OSV API)                     │
                  │ 10. Clustering (community detection)             │
                  │ 11. Process tracing (execution flows)            │
                  └──────────────────────────────────────────────────┘
```

---

## Validated Scale

| Project | Language | Files | Nodes | Edges | Time |
|---------|----------|-------|-------|-------|------|
| [zlib](https://github.com/madler/zlib) (~50K LOC) | C | 79 | 2,389 | 3,968 | 6.6s |
| [fastify](https://github.com/fastify/fastify) (~30K LOC) | JavaScript | 487 | 2,810 | 18,472 | 10.5s |
| Linux `drivers/usb` (~500K LOC) | C | 892 | 62,812 | 122,746 | 12.7s |

*Benchmarks run on Windows 11, Python 3.13, single-threaded extraction. Parallel mode (`-w 4`) is 2-3x faster.*

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture & Schema](docs/ARCHITECTURE.md) | Graph schema, node/edge types, pipeline details |
| [CLI Reference](docs/CLI.md) | All commands and options |
| [AI Agent Integration](docs/AGENT.md) | MCP setup, tools, resources, examples |
| [Deep Analysis](docs/DEEP_ANALYSIS.md) | CFG, data flow, taint, language-specific patterns |
| [Security Analysis](docs/SECURITY.md) | Security labeling, example Cypher queries |
| [Roadmap](docs/ROADMAP.md) | Development phases and status |

---

## Testing

```bash
pytest tests/ -v  # 147 tests (125 passed, 22 skipped)
```

No external services required. Tests use temporary directories with real tree-sitter parsing and git operations.

---

## License

[MIT](LICENSE)
