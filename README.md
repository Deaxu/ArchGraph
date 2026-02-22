# ArchGraph

Source code graph extraction & Cypher query tool for reverse engineering.

ArchGraph parses source code across 10 languages using tree-sitter, extracts structural and semantic relationships, and stores them in a Neo4j graph database. It provides deep analysis capabilities including control flow graphs, data flow tracking, and taint analysis for security auditing.

## Features

- **Multi-language AST parsing** — C, C++, Rust, Java, Go, JavaScript, TypeScript, Kotlin, Swift, Objective-C
- **Deep semantic analysis** — CFG, data flow, taint tracking (C/C++ via libclang, others via tree-sitter)
- **Security auditing** — Input source/dangerous sink detection, taint propagation, unsafe pattern detection
- **Git integration** — Full commit history with per-file change stats, author mapping, security fix detection, file churn analysis
- **GitHub URL support** — Clone and extract directly from GitHub URLs with branch/depth options
- **Dependency extraction** — 10 package managers (Cargo, go.mod, npm, Gradle, CMake, vcpkg, Conan, CocoaPods, SPM, Maven)
- **Neo4j storage** — Batch import with indexing, Cypher query interface
- **rlm-agent tool** — Single `query()` method with full schema in tool description

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │           GraphBuilder Pipeline           │
                    │                                          │
  Local Path ───────┤  1. Tree-sitter structural extraction    │
     or             │  2. Git history & churn enrichment       │
  GitHub URL ───────┤  3. Dependency extraction                │──── GraphData ──── Neo4j
  (auto clone)      │  4. Annotation scanning                  │      (nodes +       Store
                    │  5. Security labeling                    │       edges)
                    │  6. Clang deep analysis (C/C++)          │
                    │  7. Tree-sitter deep analysis            │
                    │  8. Deduplication                        │
                    └──────────────────────────────────────────┘
                                                                        │
                                                                        ▼
                                                               ┌─────────────────┐
                                                               ┌─────────────────┐
                                                               │  ArchGraphTool   │
                                                               │  (rlm-agent)     │
                                                               │                  │
                                                               │  query(cypher)   │
                                                               │                  │
                                                               │  description has │
                                                               │  full schema for │
                                                               │  agent context   │
                                                               └─────────────────┘
```

## Graph Schema

### Node Types

| Label | Description | Key Properties |
|-------|-------------|----------------|
| File | Source file | path, language, loc, churn_count, last_modified |
| Function | Function/method | name, file, line, is_exported, is_input_source, is_dangerous_sink |
| Class | Class definition | name, file, line |
| Struct | Struct/record | name, file, line |
| Interface | Interface/trait/protocol | name, file, line |
| Module | Module/namespace/package | name, path |
| Enum | Enumeration | name, file, line |
| Macro | Preprocessor macro | name, file, line |
| Parameter | Function parameter | name, type |
| Field | Struct/class field | name, type |
| BasicBlock | CFG basic block | index, statement_count |
| Commit | Git commit | hash, message, date, total_insertions, total_deletions, files_changed |
| Author | Commit author | name, email |
| Tag | Release tag | name, commit_hash, date |
| SecurityFix | Security-related commit | description, commit_hash |
| Dependency | External dependency | name, version |
| Annotation | Code annotation | type (TODO/HACK/FIXME/...), text |

### Edge Types

| Type | Description | Properties |
|------|-------------|------------|
| CONTAINS | File → Function/Class/Struct | |
| CALLS | Function → Function | |
| IMPORTS | File → Module | |
| INHERITS | Class → Class | |
| IMPLEMENTS | Class → Interface | |
| USES_TYPE | Function → Type | |
| DATA_FLOWS_TO | Variable data flow (intra-procedural) | from_var, to_var |
| TAINTS | Tainted data propagation (source → sink) | |
| BRANCHES_TO | CFG edge between basic blocks | |
| DEPENDS_ON | Project → External dependency | |
| MODIFIED_IN | File → Commit | lines_added, lines_deleted |
| AUTHORED_BY | Commit → Author | |
| TAGGED_AS | Commit → Tag | |
| FIXED_BY | SecurityFix → Commit | |
| AFFECTS | SecurityFix → File | |
| HAS_ANNOTATION | File → Annotation | |

## Installation

```bash
# Basic installation
pip install -e .

# With all optional language support
pip install -e ".[all]"

# With specific extras
pip install -e ".[clang]"      # C/C++ deep analysis (libclang)
pip install -e ".[kotlin]"     # Kotlin support
pip install -e ".[swift]"      # Swift support

# Development
pip install -e ".[dev]"
```

### Requirements

- Python 3.11+
- Neo4j 5.x (for graph storage)

## Quick Start

### CLI

```bash
# Extract from a local directory
archgraph extract /path/to/repo \
  --languages c,cpp,rust,java,go \
  --neo4j-uri bolt://localhost:7687 \
  --include-deep

# Extract directly from a GitHub URL
archgraph extract https://github.com/madler/zlib \
  --languages c,cpp \
  --neo4j-uri bolt://localhost:7687 \
  --clear-db

# Clone specific branch with shallow depth
archgraph extract https://github.com/user/repo \
  --branch main --depth 100

# Run Cypher queries
archgraph query "MATCH (f:Function {is_input_source: true}) RETURN f.name LIMIT 10"

# View statistics
archgraph stats

# View schema
archgraph schema
```

### Python API

```python
from pathlib import Path
from archgraph.config import ExtractConfig
from archgraph.graph.builder import GraphBuilder
from archgraph.graph.neo4j_store import Neo4jStore

# Build graph
config = ExtractConfig(
    repo_path=Path("/path/to/repo"),
    languages=["c", "cpp", "rust"],
    include_deep=True,
)
builder = GraphBuilder(config)
graph = builder.build()

# Import to Neo4j
store = Neo4jStore(uri="bolt://localhost:7687", user="neo4j", password="password")
store.connect()
store.import_graph(graph)
store.close()
```

### rlm-agent Tool

The tool exposes a single `query()` method. The full graph schema (node labels, edge types,
properties, ID format) is embedded in `tool.description` so the agent has it in context
and can write Cypher autonomously.

```python
from archgraph.tool.archgraph_tool import ArchGraphTool

with ArchGraphTool(neo4j_uri="bolt://localhost:7687") as tool:
    # The agent sees the full schema via tool.description — no discovery calls needed.
    # It writes Cypher directly:

    sources = tool.query("MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file")

    paths = tool.query("""
        MATCH p = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true})
        RETURN [n IN nodes(p) | n.name] AS chain, length(p) AS depth
    """)

    fixes = tool.query("""
        MATCH (sf:SecurityFix)-[:AFFECTS]->(f:File)
        MATCH (sf)-[:FIXED_BY]->(c:Commit)-[:AUTHORED_BY]->(a:Author)
        RETURN sf.description, f.path, a.name, c.date
    """)
```

## Deep Analysis

### C/C++ (via libclang)

Requires `pip install -e ".[clang]"` and libclang 18.1+.

- **Control Flow Graph** — BasicBlock nodes with BRANCHES_TO edges
- **Data Flow** — Reaching definitions algorithm, DATA_FLOWS_TO edges
- **Taint Tracking** — Input source to dangerous sink propagation chains
- **Macro Expansion** — EXPANDS_MACRO edges
- **Typedef Resolution** — Full typedef chain resolved to base type
- **Pointer Analysis** — void* cast and pointer arithmetic detection

### Rust, Java, Go, Kotlin, Swift (via tree-sitter)

- **Control Flow Graph** — Language-specific CFG construction
- **Data Flow** — Variable definition tracking, reaching definitions
- **Taint Tracking** — Cross-variable taint propagation
- **Language-specific patterns:**

| Language | Detected Patterns |
|----------|-------------------|
| Rust | unsafe blocks, transmute, unwrap |
| Java | reflection, serialization, synchronized, native methods |
| Go | goroutines, defer, channels, unsafe pointers |
| Kotlin | coroutines, force unwrap (!!), safe calls (?.) |
| Swift | force unwrap, optional chaining, force try, weak refs |

## Security Analysis

ArchGraph automatically labels functions based on their security characteristics:

| Label | Examples |
|-------|----------|
| `is_input_source` | recv, read, getenv, stdin, fetch, getParameter |
| `is_dangerous_sink` | memcpy, strcpy, system, eval, innerHTML, exec |
| `is_allocator` | malloc, new, Box::new, make |
| `is_crypto` | encrypt, SHA256, EVP_EncryptInit |
| `is_parser` | parse, deserialize, JSON.parse, unmarshal |
| `is_unsafe` | unsafe blocks (Rust), pointer arithmetic (C) |

### Example Queries for Agentic Code Analysis

```cypher
-- Find input-to-sink paths (potential vulnerabilities)
MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true})
RETURN src.name, sink.name, length(path)

-- Find tainted data flows
MATCH (a)-[:TAINTS]->(b)
RETURN a._id, b._id, a.name, b.name

-- Largest commits (most code churn)
MATCH (c:Commit)
WHERE c.total_insertions > 100
RETURN c.message, c.total_insertions, c.total_deletions, c.files_changed, c.date
ORDER BY c.total_insertions DESC LIMIT 10

-- High-churn files containing input source functions
MATCH (f:File)-[m:MODIFIED_IN]->(c:Commit)
WITH f, count(c) AS commits, sum(m.lines_added) AS total_added
WHERE commits > 5
MATCH (f)-[:CONTAINS]->(fn:Function {is_input_source: true})
RETURN f.path, fn.name, commits, total_added
ORDER BY commits DESC

-- Which authors touched dangerous sink files most?
MATCH (f:File)-[:CONTAINS]->(fn:Function {is_dangerous_sink: true})
MATCH (f)-[:MODIFIED_IN]->(c:Commit)-[:AUTHORED_BY]->(a:Author)
RETURN a.name, count(DISTINCT c) AS commits, collect(DISTINCT fn.name)[..5] AS sinks
ORDER BY commits DESC

-- Security fixes and affected files
MATCH (sf:SecurityFix)-[:AFFECTS]->(f:File)
MATCH (sf)-[:FIXED_BY]->(c:Commit)-[:AUTHORED_BY]->(a:Author)
RETURN sf.description, f.path, a.name, c.date

-- Release tag timeline with change stats
MATCH (c:Commit)-[:TAGGED_AS]->(t:Tag)
RETURN t.name, c.total_insertions, c.total_deletions, c.files_changed, c.date
ORDER BY c.date DESC

-- Per-file change stats in a specific commit
MATCH (f:File)-[m:MODIFIED_IN]->(c:Commit {hash: $hash})
RETURN f.path, m.lines_added, m.lines_deleted
ORDER BY m.lines_added DESC
```

## Validated Scale

| Project | Files | Nodes | Edges | Commits | Authors |
|---------|-------|-------|-------|---------|---------|
| zlib (~50K LOC) | 79 | 3,577 | 11,100 | 1,020 | 89 |

## Supported Dependency Files

| File | Package Manager |
|------|----------------|
| Cargo.toml | Rust (Cargo) |
| go.mod | Go Modules |
| package.json | npm/yarn |
| build.gradle(.kts) | Gradle |
| Podfile | CocoaPods |
| CMakeLists.txt | CMake |
| vcpkg.json | vcpkg |
| conanfile.txt | Conan |
| Package.swift | Swift Package Manager |
| pom.xml | Maven |

## Testing

```bash
# Run all tests (no Neo4j required)
pytest tests/ -v

# Run specific test module
pytest tests/test_treesitter.py -v
pytest tests/test_clang.py -v
pytest tests/test_deep.py -v
```

93 tests (89 passed, 4 skipped for optional Kotlin/Swift grammars). Tests use temporary directories with real tree-sitter parsing and git operations. No external services required.

## Project Structure

```
archgraph/
├── cli.py                  # Click CLI (extract, query, stats, schema) — GitHub URL support
├── config.py               # Constants, language maps, security patterns, ExtractConfig
├── extractors/
│   ├── base.py             # BaseExtractor ABC
│   ├── treesitter.py       # Multi-language AST parser (10 languages)
│   ├── git.py              # Commit history with numstat, author, tags, security fix detection
│   ├── dependencies.py     # 10 package manager parsers
│   ├── annotations.py      # TODO/HACK/FIXME/UNSAFE scanner
│   ├── security_labels.py  # Automatic security labeling
│   ├── clang.py            # libclang deep analysis (CFG, data flow, taint)
│   └── deep/               # Tree-sitter deep analysis engine
│       ├── engine.py       # CFG builder, reaching definitions, data flow, taint
│       ├── lang_spec.py    # LangSpec dataclass + REGISTRY
│       ├── rust.py         # Rust patterns (unsafe, transmute, unwrap)
│       ├── java.py         # Java patterns (reflection, serialization)
│       ├── go.py           # Go patterns (goroutine, defer, channel)
│       ├── kotlin.py       # Kotlin patterns (coroutine, force unwrap)
│       └── swift.py        # Swift patterns (force unwrap, optional chain)
├── graph/
│   ├── schema.py           # Node/Edge dataclass, NodeLabel/EdgeType constants
│   ├── builder.py          # 8-step pipeline orchestration
│   └── neo4j_store.py      # Neo4j connection, batch import, indexing
├── enrichment/
│   └── churn.py            # Git file churn enrichment
└── tool/
    └── archgraph_tool.py   # rlm-agent tool — single query() method, schema in description
```

## License

MIT
