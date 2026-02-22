# ArchGraph

Source code graph extraction & Cypher query tool for reverse engineering.

ArchGraph parses source code across 10 languages using tree-sitter, extracts structural and semantic relationships, and stores them in a Neo4j graph database. It provides deep analysis capabilities including control flow graphs, data flow tracking, and taint analysis for security auditing.

## Features

- **Multi-language AST parsing** — C, C++, Rust, Java, Go, JavaScript, TypeScript, Kotlin, Swift, Objective-C
- **Deep semantic analysis** — CFG, data flow, taint tracking (C/C++ via libclang, others via tree-sitter)
- **Security auditing** — Input source/dangerous sink detection, taint propagation, unsafe pattern detection
- **Git integration** — Commit history, author mapping, security fix detection, file churn analysis
- **Dependency extraction** — 10 package managers (Cargo, go.mod, npm, Gradle, CMake, vcpkg, Conan, CocoaPods, SPM, Maven)
- **Neo4j storage** — Batch import with indexing, Cypher query interface
- **rlm-agent tool** — Standalone tool with convenience methods for security analysis

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │           GraphBuilder Pipeline           │
                    │                                          │
  Source Code ──────┤  1. Tree-sitter structural extraction    │
  Repository        │  2. Git history & churn enrichment       │
                    │  3. Dependency extraction                │──── GraphData ──── Neo4j
                    │  4. Annotation scanning                  │      (nodes +       Store
                    │  5. Security labeling                    │       edges)
                    │  6. Clang deep analysis (C/C++)          │
                    │  7. Tree-sitter deep analysis            │
                    │  8. Deduplication                        │
                    └──────────────────────────────────────────┘
                                                                        │
                                                                        ▼
                                                               ┌─────────────────┐
                                                               │  ArchGraphTool   │
                                                               │  (rlm-agent)     │
                                                               │                  │
                                                               │  query()         │
                                                               │  schema()        │
                                                               │  stats()         │
                                                               │  find_attack_    │
                                                               │    surface()     │
                                                               └─────────────────┘
```

## Graph Schema

### Node Types

| Label | Description | Key Properties |
|-------|-------------|----------------|
| File | Source file | path, language, loc |
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
| Commit | Git commit | hash, message, timestamp |
| Author | Commit author | name, email |
| SecurityFix | Security-related commit | message, cve_id |
| Dependency | External dependency | name, version |
| Annotation | Code annotation | type (TODO/HACK/FIXME/...), text |

### Edge Types

| Type | Description |
|------|-------------|
| CONTAINS | File → Function/Class/Struct |
| CALLS | Function → Function |
| IMPORTS | File → Module |
| INHERITS | Class → Class |
| IMPLEMENTS | Class → Interface |
| USES_TYPE | Function → Type |
| DATA_FLOWS_TO | Variable data flow (intra-procedural) |
| TAINTS | Tainted data propagation (source → sink) |
| BRANCHES_TO | CFG edge between basic blocks |
| DEPENDS_ON | Project → External dependency |
| MODIFIED_IN | File → Commit |
| AUTHORED_BY | Commit → Author |
| FIXED_BY | File → SecurityFix |
| HAS_ANNOTATION | File → Annotation |

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
# Extract graph from a repository
archgraph extract /path/to/repo \
  --languages c,cpp,rust,java,go \
  --neo4j-uri bolt://localhost:7687 \
  --include-deep

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

```python
from archgraph.tool.archgraph_tool import ArchGraphTool

with ArchGraphTool(neo4j_uri="bolt://localhost:7687") as tool:
    # Find attack surface
    sources = tool.find_attack_surface()

    # Trace data flow from input to dangerous sink
    paths = tool.find_dangerous_paths("recv", max_depth=5)

    # Find security-related commits
    fixes = tool.find_security_fixes()

    # Find high churn files (potential bug magnets)
    churn = tool.find_high_churn_files(threshold=10)

    # Custom Cypher query
    results = tool.query("""
        MATCH (f:Function {is_input_source: true})-[:CALLS*1..5]->(s:Function {is_dangerous_sink: true})
        RETURN f.name AS source, s.name AS sink
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

### Example Security Queries

```cypher
-- Find input-to-sink paths (potential vulnerabilities)
MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true})
RETURN src.name, sink.name, length(path)

-- Find tainted data flows
MATCH (a)-[:TAINTS]->(b)
RETURN a._id, b._id, a.name, b.name

-- Find unsafe Rust functions with external input
MATCH (f:Function {is_unsafe: true})<-[:CALLS]-(caller:Function {is_input_source: true})
RETURN f.name, f.file, caller.name

-- Find high-churn files with security annotations
MATCH (f:File {change_count: c})-[:HAS_ANNOTATION]->(a:Annotation {type: 'SECURITY'})
WHERE c > 10
RETURN f.path, c, a.text
```

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

Tests use temporary directories with real tree-sitter parsing and git operations. No external services required.

## Project Structure

```
archgraph/
├── cli.py                  # Click CLI (extract, query, stats, schema)
├── config.py               # Constants, language maps, security patterns, ExtractConfig
├── extractors/
│   ├── base.py             # BaseExtractor ABC
│   ├── treesitter.py       # Multi-language AST parser (10 languages)
│   ├── git.py              # Commit history, author, security fix detection
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
    └── archgraph_tool.py   # rlm-agent tool (query, schema, stats, convenience methods)
```

## License

MIT
