<p align="center">
  <img src="assets/banner.svg" alt="ArchGraph" width="700"/>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"/></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Server-green.svg" alt="MCP Server"/></a>
  <img src="https://img.shields.io/badge/tests-137%20passed-brightgreen.svg" alt="Tests"/>
</p>

<p align="center">
  <b>Security-first code intelligence for AI agents.</b><br/>
  Parses <b>10 languages</b>, builds a knowledge graph with <b>taint analysis</b>, <b>CVE detection</b>, and <b>clustering</b>.<br/>
  Connect to any AI agent via <b>MCP</b> — Cursor, Claude Code, Windsurf, and more.
</p>

---

## Why ArchGraph?

Other tools help you *understand* code. **ArchGraph helps you *secure* it.**

| | **ArchGraph** | **Code Search** | **AST Parsers** | **SAST Tools** |
|--|---------------|-----------------|-----------------|----------------|
| **Taint Analysis** | ✅ Input → Sink | ❌ | ❌ | ✅ |
| **CVE Detection** | ✅ Auto via OSV | ❌ | ❌ | Partial |
| **CFG / Data Flow** | ✅ libclang + tree-sitter | ❌ | Partial | ✅ |
| **MCP for AI Agents** | ✅ 7 tools | ❌ | ❌ | ❌ |
| **Functional Clustering** | ✅ Community detection | ❌ | ❌ | ❌ |
| **Execution Tracing** | ✅ Entry → Sink flows | ❌ | ❌ | ❌ |
| **Export (JSON/GraphML)** | ✅ | ❌ | ❌ | Partial |
| **Local-first** | ✅ Neo4j | Varies | ✅ | Varies |
| **License** | MIT | Varies | Varies | Often proprietary |

---

## Quick Start

```bash
# Install
pip install archgraph

# Extract (auto-detects languages)
archgraph extract /path/to/repo -w 4

# Query the graph
archgraph query "MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file"

# Start web dashboard
archgraph serve --port 8080

# Generate HTML security report
archgraph report /path/to/repo
```

**With Docker (Neo4j included):**
```bash
docker compose up -d neo4j           # password: archgraph
archgraph extract /path/to/repo --neo4j-password archgraph
```

---

## 🤖 AI Agent Integration (MCP)

ArchGraph exposes 7 tools and 4 resources to any MCP-compatible agent.

### Setup

```bash
# Index your repo
archgraph extract . --include-cve --include-clustering

# Start MCP server
archgraph mcp
```

**Connect your agent:**

| Agent | Command |
|-------|---------|
| Claude Code | `claude mcp add archgraph -- archgraph mcp` |
| Cursor | Add to `~/.cursor/mcp.json` |
| Windsurf | Add to MCP config |
| OpenCode | Add to `~/.config/opencode/config.json` |

### What Your Agent Gets

**Tools:** `query`, `impact`, `context`, `detect_changes`, `find_vulnerabilities`, `cypher`, `stats`

**Resources:** `archgraph://schema`, `archgraph://security`, `archgraph://clusters`, `archgraph://processes`

### Example Conversation

```
You: "Are there any buffer overflow risks in the network code?"

Agent:
1. Queries input sources in network files
2. Traces taint paths to dangerous sinks
3. Reports: "Found 2 paths:
   - net_recv() → memcpy() in src/net/handler.c (depth: 3)
   - read_packet() → strcpy() in src/net/parser.c (depth: 4)
   Both reach dangerous sinks without validation."
```

---

## 🔒 Security Features

**Automatic labeling** — Every function gets security labels:
- `is_input_source` — reads external data (recv, read, fetch, ...)
- `is_dangerous_sink` — dangerous operations (memcpy, exec, eval, ...)
- `is_allocator`, `is_crypto`, `is_parser` — additional categories
- `risk_score` — 0-100 risk score based on labels

**Taint path detection:**
```cypher
MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..8]->(sink:Function {is_dangerous_sink: true})
RETURN src.name, sink.name, length(path) AS depth
```

**CVE enrichment:**
```bash
archgraph extract . --include-cve    # Queries OSV API automatically
```

---

## All Commands

| Command | Description |
|---------|-------------|
| `extract` | Extract code graph from repository |
| `query` | Run Cypher queries against the graph |
| `stats` | Show node/edge statistics |
| `schema` | Show graph schema |
| `diff` | Compare repo state vs stored graph |
| `impact` | Blast radius analysis for a function |
| `export` | Export to JSON, GraphML, or CSV |
| `report` | Generate HTML security report |
| `serve` | Start web dashboard |
| `mcp` | Start MCP server for AI agents |
| `skills` | Generate AI agent skill files |
| `repos` | List indexed repositories |

---

## Use Cases

### Security Audit
```bash
archgraph extract /target -l c,cpp --include-cve --include-clang
archgraph query "MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true}) RETURN src.name, sink.name"
```

### Code Review
```bash
archgraph diff /path/to/repo
archgraph impact "func:src/api.c:handle:42" --direction both
```

### Reverse Engineering
```bash
archgraph extract /binary/project -l c,cpp,rust --include-clang --include-deep
archgraph query "MATCH (f:Function) WHERE f.is_exported = true RETURN f.name, f.file"
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
                  │  8. Churn enrichment                             │       └── Export/Report
                  │  9. CVE enrichment (OSV API)                     │
                  │ 10. Clustering (community detection)             │
                  │ 11. Process tracing (execution flows)            │
                  └──────────────────────────────────────────────────┘
```

---

## Benchmarks

| Project | Language | Files | Nodes | Edges | Time |
|---------|----------|-------|-------|-------|------|
| [zlib](https://github.com/madler/zlib) (~50K LOC) | C | 79 | 2,389 | 3,968 | 6.6s |
| [fastify](https://github.com/fastify/fastify) (~30K LOC) | JavaScript | 487 | 2,810 | 18,472 | 10.5s |
| Linux `drivers/usb` (~500K LOC) | C | 892 | 62,812 | 122,746 | 12.7s |

*Benchmarks: Windows 11, Python 3.13, single-threaded. Parallel mode (`-w 4`) is 2-3x faster.*

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture & Schema](docs/ARCHITECTURE.md) | Graph schema, node/edge types, pipeline |
| [CLI Reference](docs/CLI.md) | All commands and options |
| [AI Agent Integration](docs/AGENT.md) | MCP setup, tools, examples |
| [Security Analysis](docs/SECURITY.md) | Security labeling, Cypher queries |
| [Deep Analysis](docs/DEEP_ANALYSIS.md) | CFG, data flow, taint tracking |
| [Roadmap](docs/ROADMAP.md) | Development phases |

---

## Testing

```bash
pytest tests/ -v  # 137 passed, 22 skipped
```

No external services required. Tests use temporary directories with real tree-sitter parsing and git operations.

---

## License

[MIT](LICENSE)
