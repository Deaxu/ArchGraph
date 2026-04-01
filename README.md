<p align="center">
  <img src="assets/banner.svg" alt="ArchGraph" width="700"/>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"/></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Built%20for%20Agents-green.svg" alt="Built for AI Agents via MCP"/></a>
  <img src="https://img.shields.io/badge/tests-234%20passed-brightgreen.svg" alt="Tests"/>
</p>

<p align="center">
  <b>Code intelligence for AI agents and security auditing.</b><br/>
  Parses 11 languages, builds a knowledge graph with compiler-backed call resolution,<br/>
  taint analysis, CVE detection, and clustering. Expose to any agent via MCP.
</p>

<p align="center">
  <a href="docs/CLI.md">CLI</a> &middot;
  <a href="docs/AGENT.md">MCP & API</a> &middot;
  <a href="docs/SECURITY.md">Security</a> &middot;
  <a href="docs/ARCHITECTURE.md">Architecture</a> &middot;
  <a href="docs/BENCHMARKS.md">Benchmarks</a> &middot;
  <a href="docs/ROADMAP.md">Roadmap</a>
</p>

---

## Quick Start

```bash
pip install archgraph                         # 1. Install
docker compose up -d neo4j                    # 2. Start Neo4j
archgraph extract /path/to/your/repo          # 3. Extract
```

Auto-detects languages, runs SCIP indexers for compiler-backed call resolution, extracts git history, scans dependencies, and imports into Neo4j.

### Use with an AI agent

```bash
archgraph mcp                                 # Start MCP server (12 tools)
claude mcp add archgraph -- archgraph mcp     # Connect to Claude Code
```

Also works with Cursor, Windsurf, and any MCP-compatible client. See [MCP & API docs](docs/AGENT.md).

### Use from the command line

```bash
archgraph search -n "auth*" -t function       # Find functions
archgraph impact "func:src/auth.py:validate:42"  # Blast radius
archgraph query "MATCH (f:Function) RETURN f"    # Raw Cypher
```

### Use from Python

```python
from archgraph import ArchGraph

ag = ArchGraph()
ag.search(name="validate*", type="function")
ag.impact("func:src/auth.py:validate:42", direction="both")
ag.query("MATCH (f:Function {is_input_source: true}) RETURN f.name")
ag.close()
```

---

## Languages

| Language | Call Resolution | You Need |
|----------|----------------|----------|
| TypeScript | SCIP (compiler-backed) | Node.js |
| JavaScript | SCIP (compiler-backed) | Node.js |
| Python | SCIP (compiler-backed) | Node.js |
| Rust | SCIP (compiler-backed) | Rust toolchain |
| Go | SCIP (compiler-backed) | Go toolchain |
| Java | SCIP (compiler-backed) | JDK |
| Kotlin | SCIP (compiler-backed) | JDK + `pip install archgraph[kotlin]` |
| C / C++ | Heuristic (name-based) | `pip install archgraph[clang]` for deep analysis |
| Swift | Heuristic (name-based) | `pip install archgraph[swift]` |
| Objective-C | Heuristic (name-based) | `pip install archgraph[objc]` |

SCIP indexers are downloaded automatically on first use. Install all optional grammars with `pip install archgraph[all]`.

---

## Key Features

**Security Analysis** -- automatic labeling of input sources, dangerous sinks, crypto ops, allocators, and parsers. Taint tracking via libclang (C/C++) and tree-sitter (Rust, Java, Go, Kotlin, Swift). CVE detection via [OSV](https://osv.dev). See [Security docs](docs/SECURITY.md).

**12 MCP Tools** -- `query`, `search`, `search_calls`, `context`, `impact`, `detect_changes`, `find_vulnerabilities`, `source`, `extract`, `stats`, `repos`, `cypher`. See [MCP & API docs](docs/AGENT.md).

**Full Python API** -- `from archgraph import ArchGraph` with 12 methods matching every MCP tool. See [API Reference](docs/AGENT.md#python-api).

**Blast Radius** -- trace upstream callers and downstream callees with resolution confidence (SCIP vs heuristic). See [Benchmarks](docs/BENCHMARKS.md).

---

## Comparison

| Feature | **ArchGraph** | **GitNexus** | **Sourcegraph** | **CodeQL** |
|---------|---------------|--------------|-----------------|------------|
| **License** | MIT | PolyForm NC | BSL | Proprietary |
| **Languages** | 11 | 15 | 40+ | 10+ |
| **MCP Server** | 12 tools | 11 tools | -- | -- |
| **SCIP Resolution** | 6 languages | -- | Internal | -- |
| **Taint Analysis** | libclang + tree-sitter | -- | -- | QL queries |
| **CVE Detection** | OSV API | -- | Yes | Advisory DB |
| **Local-first** | Yes | Yes | No (SaaS) | Yes |
| **Graph DB** | Neo4j (Cypher) | LadybugDB | PostgreSQL | Custom |

---

## Development

```bash
git clone https://github.com/Deaxu/ArchGraph.git
cd ArchGraph
pip install -e ".[dev,all]"
pytest tests/ -v                              # 234 passed, 22 skipped
```

Tests run without Neo4j -- they use temporary directories with real tree-sitter parsing and git operations.

---

<p align="center">
  <a href="LICENSE">MIT License</a>
</p>
