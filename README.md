<p align="center">
  <img src="assets/banner.svg" alt="ArchGraph" width="700"/>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"/></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11%2B-blue.svg" alt="Python 3.11+"/></a>
</p>

<p align="center">
  Source code graph extraction and Cypher query tool for reverse engineering.<br/>
  Parses <b>10 languages</b>, builds a <b>Neo4j</b> knowledge graph with CFG, data flow, taint analysis, and CVE enrichment.
</p>

---

## Highlights

- **10 languages** — C, C++, Rust, Java, Go, JavaScript, TypeScript, Kotlin, Swift, Objective-C
- **Deep analysis** — CFG, data flow, taint tracking via libclang (C/C++) and tree-sitter
- **Security auditing** — Input/sink detection, taint propagation, unsafe patterns, CVE enrichment
- **Git integration** — Commit history, per-file change stats, author mapping, security fix detection
- **Incremental extraction** — Only re-extract changed files via manifest-based change detection
- **APOC batch import** — Auto-detected APOC procedures for optimized Neo4j bulk import
- **Graph diff** — Compare current repo state against stored graph (added/removed/modified nodes)
- **Parallel pipeline** — ThreadPoolExecutor-based multi-threaded extraction
- **CVE enrichment** — Automatic vulnerability detection via [OSV](https://osv.dev) API
- **rlm-agent tool** — `query()`, `find_vulnerabilities()`, and `diff_summary()` methods

## Installation

```bash
pip install -e .

# With all optional extras
pip install -e ".[all]"

# Development
pip install -e ".[dev]"
```

**Requirements:** Python 3.11+, Neo4j 5.x (for graph storage)

## Quick Start

```bash
# Extract from local repo
archgraph extract /path/to/repo -l c,cpp,rust -w 4

# Extract from GitHub URL
archgraph extract https://github.com/madler/zlib -l c,cpp --clear-db

# With CVE enrichment
archgraph extract /path/to/repo -l c,cpp --include-cve

# Run Cypher query
archgraph query "MATCH (f:Function {is_input_source: true}) RETURN f.name LIMIT 10"

# Stats & schema
archgraph stats
archgraph schema
```

## Docker

```bash
# Start Neo4j
docker compose up -d neo4j

# Extract (mount your repo)
docker compose run archgraph extract /data/repo -l c,cpp,rust -w 4

# Query
docker compose run archgraph query "MATCH (f:Function) RETURN f.name LIMIT 10"

# Build with optional extras (clang, kotlin, swift, objc)
docker build --build-arg INSTALL_EXTRAS=all -t archgraph .
```

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
)
graph = GraphBuilder(config).build()
```

## Architecture

```
                  ┌────────────────────────────────────────────────┐
                  │           GraphBuilder Pipeline (9 steps)       │
                  │                                                │
  Local Path ─────┤  1. Tree-sitter structural extraction          │
     or           │  2. Git history                                │
  GitHub URL ─────┤  3. Dependency extraction                      │──── Neo4j
  (auto clone)    │  4. Annotation scanning                        │     Store
                  │  5. Security labeling                          │
                  │  6. Clang deep analysis (C/C++)                │
                  │  7. Tree-sitter deep analysis (Rust/Java/Go/…) │
                  │  8. Churn enrichment                           │
                  │  9. CVE enrichment (OSV API)                   │
                  └────────────────────────────────────────────────┘
```

## Validated Scale

| Project | Files | Nodes | Edges | Commits | Authors |
|---------|-------|-------|-------|---------|---------|
| zlib (~50K LOC) | 79 | 3,577 | 11,100 | 1,020 | 89 |

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture & Schema](docs/ARCHITECTURE.md) | Graph schema, node/edge types, pipeline details |
| [CLI Reference](docs/CLI.md) | All commands and options |
| [Deep Analysis](docs/DEEP_ANALYSIS.md) | CFG, data flow, taint, language-specific patterns |
| [Security Analysis](docs/SECURITY.md) | Security labeling, example Cypher queries |
| [Agent Integration](docs/AGENT.md) | rlm-agent tool usage and examples |
| [Roadmap](docs/ROADMAP.md) | Development phases and status |

## Testing

```bash
pytest tests/ -v  # 102 tests (98 passed, 4 skipped)
```

No external services required. Tests use temporary directories with real tree-sitter parsing and git operations.

## License

[MIT](LICENSE)
