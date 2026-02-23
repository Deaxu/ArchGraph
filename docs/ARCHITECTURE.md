# Architecture & Graph Schema

## Project Structure

```
archgraph/
├── cli.py                  # Click CLI — extract, query, stats, schema + GitHub URL support
├── config.py               # Constants, language maps, security patterns, ExtractConfig
├── extractors/
│   ├── base.py             # BaseExtractor ABC
│   ├── treesitter.py       # Multi-language AST parser (10 languages, thread-safe parallel)
│   ├── git.py              # Commit history + numstat, author, tags, security fix detection
│   ├── dependencies.py     # 10 package manager parsers (single os.walk traversal)
│   ├── annotations.py      # TODO/HACK/UNSAFE/FIXME/BUG/XXX/SECURITY/VULNERABILITY
│   ├── security_labels.py  # Automatic security labeling
│   ├── clang.py            # libclang deep analysis (CFG, data flow, taint, macro, typedef)
│   └── deep/               # Tree-sitter deep analysis engine
│       ├── engine.py       # CFG builder, reaching definitions, data flow, taint
│       ├── lang_spec.py    # LangSpec dataclass + REGISTRY
│       ├── rust.py / java.py / go.py / kotlin.py / swift.py
├── graph/
│   ├── schema.py           # Node/Edge dataclass, NodeLabel/EdgeType constants
│   ├── builder.py          # 9-step pipeline (parallel/sequential) orchestration
│   └── neo4j_store.py      # Neo4j connection, batch import, indexing, query
├── enrichment/
│   ├── churn.py            # Git file churn enrichment
│   └── cve.py              # CVE enrichment via OSV API
├── manifest.py             # Incremental extraction state (JSON manifest I/O, change detection)
└── tool/
    └── archgraph_tool.py   # rlm-agent tool — query() + find_vulnerabilities() + diff_summary()
```

## Pipeline

The `GraphBuilder` orchestrates 9 extraction steps. It supports two modes:

- **Sequential** (`workers=1`): Steps run one after another
- **Parallel** (`workers>1`): Independent steps run concurrently via `ThreadPoolExecutor`

### Parallel Execution Groups

```
Group A (concurrent):  Step 1 (tree-sitter) | Step 2 (git) | Step 3 (deps) | Step 4 (annotations)
                                    ↓
Step 5:                Security labeling (needs merged Function nodes)
                                    ↓
Group C (concurrent):  Step 6 (clang) | Step 7 (deep analysis)
                                    ↓
Step 8:                Churn enrichment (needs File nodes + git data)
Step 9:                CVE enrichment (needs Dependency nodes)
                                    ↓
                       Deduplication → Final graph
```

### Incremental Extraction

When `--incremental` is enabled, ArchGraph only re-extracts changed files:

```
1. Load manifest (.archgraph/manifest.json)
2. Scan current files → compute SHA-256 hashes
3. Compute ChangeSet (added/modified/deleted files, deps_changed)
4. If no changes → skip extraction
5. If git diverged → fallback to full extraction
6. Run only relevant extractors on changed files
7. Save updated manifest
```

**Manifest format** (`.archgraph/manifest.json`):
```json
{
  "version": 1,
  "extracted_at": "2026-02-23T10:00:00Z",
  "repo_path": "/path/to/repo",
  "git_head": "abc123def456",
  "dependencies_hash": "sha256hex",
  "files": {
    "src/main.c": {"hash": "sha256hex", "size": 1024, "language": "c"}
  }
}
```

### APOC Batch Import

If the Neo4j APOC plugin is detected, `import_graph()` automatically uses `apoc.periodic.iterate` for optimized batching:
- **Nodes**: `parallel: true`, `batchSize: 5000`
- **Edges**: `parallel: false` (avoids deadlocks from concurrent MATCH+MERGE)
- Falls back to standard UNWIND if APOC is not installed

### Thread Safety Rules

- `ts.Language` objects are thread-safe — shared across threads
- `ts.Parser` objects are NOT thread-safe — `threading.local()` per thread
- `GraphData.merge()` runs in the main thread after `futures.result()`
- libclang `Index` is not thread-safe — each thread creates its own `Index`

## Graph Schema

### Node Types

| Label | Description | Key Properties |
|-------|-------------|----------------|
| File | Source file | path, language, size, lines, hash, churn_count, last_modified |
| Function | Function/method | name, file, line_start, line_end, params, return_type, is_exported, is_input_source, is_dangerous_sink, is_allocator, is_crypto, is_parser, is_unsafe |
| Class | Class definition | name, file, line_start, line_end, is_abstract |
| Struct | Struct/record | name, file, line_start |
| Interface | Interface/trait/protocol | name, file, line_start |
| Enum | Enumeration | name, file |
| Module | Module/namespace/package | name, path |
| Macro | Preprocessor macro | name, file, body |
| Parameter | Function parameter | name, index, function |
| Field | Struct/class field | name, type |
| BasicBlock | CFG basic block | block_index, stmt_count, function, file |
| Commit | Git commit | hash, message, date, total_insertions, total_deletions, files_changed |
| Author | Commit author | name, email |
| Tag | Release tag | name, commit_hash, date |
| SecurityFix | Security-related commit | description, commit_hash |
| Dependency | External dependency | name, version, source |
| Vulnerability | Known vulnerability (CVE/GHSA/PYSEC) | vuln_id, summary, severity, aliases |
| Annotation | Code annotation | type, text, line |
| BuildConfig | Build configuration | name, path |

### Edge Types

| Type | Source → Target | Properties |
|------|-----------------|------------|
| CONTAINS | File → Function/Class/Struct/Enum/Macro, Function → BasicBlock | |
| CALLS | Function → Function | |
| IMPORTS | File → Module | raw |
| INHERITS | Class → Class | |
| IMPLEMENTS | Class/Struct → Interface | |
| USES_TYPE | Function → Type | |
| OVERRIDES | Function → Function | |
| EXPANDS_MACRO | File → Macro | line |
| DATA_FLOWS_TO | Function → Function (self-edge) | from_var, to_var, from_line, to_line |
| TAINTS | funcref → funcref | via_function, via_variable, file |
| BRANCHES_TO | BasicBlock → BasicBlock | |
| MODIFIED_IN | File → Commit | lines_added, lines_deleted |
| AUTHORED_BY | Commit → Author | |
| TAGGED_AS | Commit → Tag | |
| PARENT | Commit → Commit | |
| DEPENDS_ON | Module → Dependency | |
| FIXED_BY | SecurityFix → Commit | |
| AFFECTS | SecurityFix → File | |
| HAS_ANNOTATION | File → Annotation | |
| AFFECTED_BY | Dependency → Vulnerability | |
| COMPILED_WITH | File → BuildConfig | |

### Node ID Format

All nodes have a unique `_id` property following the pattern: `{type}:{path}:{name}:{line}`

Examples:
- `func:src/main.c:parse_data:42`
- `file:src/inflate.c`
- `commit:abc123def456`
- `dep:openssl`
- `vuln:CVE-2024-1234`
- `bb:src/main.c:parse_data:0`

### Neo4j Conventions

- All nodes carry an additional `_Node` label for cross-label queries
- `_id` property has a unique constraint
- Use `MATCH (n:_Node {_id: $id})` for exact lookups
- `funcref:` prefix indicates an unresolved call target (no definition in codebase)

## ExtractConfig

```python
@dataclass
class ExtractConfig:
    repo_path: Path
    languages: list[str] = ["c", "cpp", "rust", "java", "go"]
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j"
    neo4j_database: str = "neo4j"
    include_git: bool = True
    include_deps: bool = True
    include_annotations: bool = True
    include_security_labels: bool = True
    max_file_size: int = 1_000_000
    git_max_commits: int = 10_000
    include_clang: bool = False
    clang_compile_commands: Path | None = None
    clang_extra_args: list[str] = []
    include_deep: bool = False
    workers: int = 0          # 0=auto, 1=sequential
    include_cve: bool = False
    osv_batch_size: int = 1000
    incremental: bool = False  # Enable incremental extraction
```

## Graph Diff

`GraphData.diff(newer)` compares two graph snapshots:

- **NodeChange**: node_id, label, changed_properties (prop → (old, new))
- **GraphDiff**: nodes_added, nodes_removed, nodes_modified, edges_added, edges_removed

Used by `archgraph diff` CLI command and `ArchGraphTool.diff_summary()`.
