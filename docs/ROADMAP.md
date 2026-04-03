# Roadmap

## Phase 1: Core Extraction ✅ COMPLETE

- [x] Tree-sitter multi-language parser (11 languages)
- [x] Git history extraction (commits, authors, tags, numstat)
- [x] Dependency extraction (10 package managers)
- [x] Annotation scanning (TODO, HACK, FIXME, etc.)
- [x] Security labeling (input sources, dangerous sinks, allocators, crypto, parsers)
- [x] Neo4j batch import with APOC support
- [x] CLI with extract, query, stats, schema commands
- [x] Python API (ExtractConfig + GraphBuilder)
- [x] Docker support

## Phase 2: Deep Analysis ✅ COMPLETE

- [x] libclang integration for C/C++ (CFG, data flow, taint analysis)
- [x] Tree-sitter deep analysis for Rust, Java, Go, Kotlin, Swift
- [x] Security fix detection in git commits
- [x] Churn enrichment (file change frequency)
- [x] CVE enrichment via OSV API
- [x] Graph diff (compare repo state vs stored graph)
- [x] Incremental extraction with manifest-based change detection

## Phase 3: AI Agent Integration ✅ COMPLETE

- [x] **MCP Server** — 12 tools, 4 resources for any MCP-compatible agent
  - [x] `query` / `cypher` — Cypher queries
  - [x] `impact` — Blast radius analysis
  - [x] `context` — 360° symbol view
  - [x] `detect_changes` — Git-diff impact
  - [x] `find_vulnerabilities` — CVE detection
  - [x] `stats` — Graph statistics
  - [x] `source` — Source code retrieval (body storage)
  - [x] `extract` — Repo extraction (clone + SCIP + import)
  - [x] `search` — Symbol search (name/type/file pattern)
  - [x] `repos` — List indexed repositories
  - [x] `search_calls` — Call chain search with transitive traversal
- [x] **Python API** — `from archgraph import ArchGraph` — 11 methods, full parity with MCP
- [x] **rlm-agent Tool** — `ArchGraphTool` with 11 tool methods
- [x] **Clustering** — Community detection (greedy modularity)
- [x] **Process Tracing** — Execution flow analysis from entry points
- [x] **Web Dashboard** — Interactive graph exploration with FastAPI
- [x] **Hybrid Search** — BM25 + graph relevance + RRF
- [x] **Multi-Repo Registry** — Global index at `~/.archgraph/registry.json`
- [x] **Agent Skills Generation** — Security-focused skill files for AI agents
- [x] **Impact Analysis** — Blast radius computation with risk assessment

## Phase 3.5: Code Intelligence ✅ COMPLETE

- [x] **Code Body Storage** — Source code in graph nodes (function body, class shell)
  - [x] `include_body=True` default, `--no-body` to disable
  - [x] 50KB max body size with line-aligned truncation
  - [x] Class shell extraction (method bodies → `{ ... }`)
- [x] **SCIP Call Resolution** — Compiler-backed cross-reference accuracy
  - [x] TypeScript/JavaScript via `@sourcegraph/scip-typescript` (auto-install)
  - [x] Rust via `rust-analyzer` (auto-install via rustup)
  - [x] Go via `scip-go` (auto-install via go install)
  - [x] Java/Kotlin via `scip-java` (coursier-based)
  - [x] Python via `@sourcegraph/scip-python` (auto-install + Windows auto-patch)
  - [x] C/C++ via `scip-clang` (auto-download Linux/macOS, heuristic fallback)
  - [x] Heuristic fallback for unsupported languages
  - [x] Compiler-backed resolution with full type information
- [x] **Qualifier Preservation** — `Counter.increment()` → qualifier + name tracked
- [x] **Named Import Parsing** — JS/TS/Rust/Java/Go import symbol extraction

## Phase 4: Advanced Features 🚧 IN PROGRESS

- [ ] **Embeddings** — Semantic search with vector embeddings
- [ ] **Cross-repo analysis** — Dependency tracking across repositories
- [ ] **Real-time updates** — File watcher for automatic re-indexing
- [ ] **Visualization** — Interactive graph visualization (D3.js/ForceGraph)
- [ ] **IDE plugins** — VS Code / JetBrains integration
- [ ] **Performance** — Rust-based parser for 10x speed improvement
- [ ] **Cloud deployment** — Managed Neo4j + hosted MCP server
- [x] **C/C++ SCIP** — scip-clang integration for compiler-backed C/C++ resolution
- [x] **JS/TS/Python Deep Analysis** — CFG, data flow, taint, pattern detection

## Comparison with Similar Tools

| Feature | **ArchGraph** | **GitNexus** | **Sourcegraph** | **CodeQL** |
|---------|---------------|--------------|-----------------|------------|
| **License** | MIT | PolyForm NC | BSL | Proprietary |
| **Language** | Python | TypeScript | Go | C++/JS |
| **Graph DB** | Neo4j | LadybugDB | PostgreSQL | Custom |
| **Languages** | 11 | 15 | 40+ | 10+ |
| **MCP Server** | ✅ 12 tools | ✅ 11 tools | ❌ | ❌ |
| **SCIP Resolution** | ✅ 6 languages | ❌ | ✅ (internal) | ❌ |
| **Python API** | ✅ 12 methods | ❌ | ❌ | ❌ |
| **Body Storage** | ✅ | ✅ | ❌ | ❌ |
| **Web UI** | ✅ FastAPI | ✅ React + Sigma.js | ✅ | ❌ |
| **Taint Analysis** | ✅ libclang | ❌ | ❌ | ✅ |
| **CVE Detection** | ✅ OSV API | ❌ | ✅ | ✅ |
| **Clustering** | ✅ Leiden | ✅ Leiden | ❌ | ❌ |
| **Process Tracing** | ✅ | ✅ | ❌ | ❌ |
| **Hybrid Search** | ✅ BM25+Graph | ✅ BM25+Semantic | ✅ | ❌ |
| **Local-first** | ✅ | ✅ | ❌ | ✅ |
| **Incremental** | ✅ | ✅ | ✅ | ❌ |
| **Agent Skills** | ✅ Security | ✅ General | ❌ | ❌ |
| **Impact Analysis** | ✅ | ✅ | Partial | ✅ |

### Why ArchGraph?

1. **Security-first** — Built for security auditing, not just code search
2. **Taint analysis** — Tracks data flow from input sources to dangerous sinks
3. **MIT license** — Free for commercial use
4. **Python ecosystem** — Easy to extend and integrate
5. **Neo4j power** — Full Cypher query language, mature graph database
6. **MCP native** — First-class AI agent integration
