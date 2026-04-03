# CLI Reference

## Commands

### `extract`

Extract code graph from a repository and import into Neo4j.

```bash
archgraph extract REPO_PATH [OPTIONS]
```

**Arguments:**
- `REPO_PATH` — Local directory or git URL (https://, git@, ssh://)

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-l, --languages` | `auto` | Comma-separated languages or `auto` to detect |
| `-b, --branch` | — | Branch to clone (for git URLs) |
| `-d, --depth` | — | Clone depth (for git URLs) |
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j bolt URI |
| `--neo4j-user` | `neo4j` | Neo4j username |
| `--neo4j-password` | `archgraph` | Neo4j password |
| `--neo4j-database` | `neo4j` | Neo4j database name |
| `--include-git/--no-git` | `True` | Include git history extraction |
| `--include-deps/--no-deps` | `True` | Include dependency extraction |
| `--include-annotations/--no-annotations` | `True` | Include annotations |
| `--include-clang/--no-clang` | `False` | Enable clang deep analysis |
| `--include-deep/--no-deep` | `True` | Enable tree-sitter deep analysis |
| `--compile-commands` | — | Path to compile_commands.json |
| `-w, --workers` | `0` | Worker threads (0=auto, 1=sequential) |
| `--include-cve/--no-cve` | `False` | Enable CVE enrichment |
| `--include-clustering/--no-clustering` | `False` | Enable cluster detection |
| `--include-process/--no-process` | `False` | Enable process tracing |
| `--include-body/--no-body` | `True` | Store source code bodies in graph nodes |
| `--max-body-size` | `51200` | Max body size in bytes (truncate beyond) |
| `--incremental/--no-incremental` | `False` | Incremental extraction |
| `--clear-db/--no-clear-db` | `False` | Clear database before import |
| `-v, --verbose` | `False` | Verbose output |

**Examples:**

```bash
# Basic extraction
archgraph extract /path/to/repo -l c,cpp,rust -w 4

# From GitHub URL
archgraph extract https://github.com/madler/zlib -l c,cpp --clear-db

# Full security analysis
archgraph extract /path/to/repo -l c,cpp --include-cve --include-clang

# With clustering and process tracing
archgraph extract /path/to/repo --include-clustering --include-process

# Incremental extraction (only changed files)
archgraph extract /path/to/repo --incremental

# Deep analysis for Rust/Java/Go
archgraph extract /path/to/repo -l rust,java,go --include-deep
```

---

### `query`

Execute a Cypher query against the graph database.

```bash
archgraph query CYPHER_QUERY [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j bolt URI |
| `--neo4j-user` | `neo4j` | Neo4j username |
| `--neo4j-password` | `archgraph` | Neo4j password |
| `--neo4j-database` | `neo4j` | Neo4j database name |

**Examples:**

```bash
# Find all input sources
archgraph query "MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file"

# Find input-to-sink paths
archgraph query "MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true}) RETURN src.name, sink.name, length(path)"

# Find vulnerable dependencies
archgraph query "MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability) RETURN d.name, v.vuln_id, v.severity"
```

---

### `search`

Search for symbols by name, type, or file pattern. No Cypher needed.

```bash
archgraph search [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-n, --name` | — | Symbol name (supports `*` wildcards) |
| `-t, --type` | — | Filter: function, class, struct, interface, enum, module, file |
| `-f, --file-pattern` | — | File path pattern (supports `*` wildcards) |
| `-l, --limit` | `20` | Max results |
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j bolt URI |

**Examples:**

```bash
# Find all functions named "main"
archgraph search -n main -t function

# Find classes matching a pattern
archgraph search -n "*Handler" -t class

# Find all symbols in auth files
archgraph search -f "*auth*"
```

---

### `stats`

Show graph database statistics.

```bash
archgraph stats [OPTIONS]
```

Shows node and edge counts per type.

---

### `schema`

Show the graph database schema.

```bash
archgraph schema [OPTIONS]
```

Displays node labels, relationship types, and property keys.

---

### `diff`

Show differences between the current repo state and the stored graph.

```bash
archgraph diff REPO_PATH [OPTIONS]
```

Extracts the current repo state and compares it with the graph stored in Neo4j to show added, removed, and modified nodes/edges.

---

### `mcp` ⭐ NEW

Start MCP server for AI agent integration.

```bash
archgraph mcp [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j bolt URI |
| `--neo4j-user` | `neo4j` | Neo4j username |
| `--neo4j-password` | `archgraph` | Neo4j password |
| `--neo4j-database` | `neo4j` | Neo4j database name |

**Connect to agents:**

```bash
# Claude Code
claude mcp add archgraph -- archgraph mcp

# Or configure in editor MCP settings
```

---

### `serve` ⭐ NEW

Start web dashboard for interactive graph exploration.

```bash
archgraph serve [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `127.0.0.1` | Bind host |
| `-p, --port` | `8080` | Bind port |
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j bolt URI |
| `--neo4j-user` | `neo4j` | Neo4j username |
| `--neo4j-password` | `archgraph` | Neo4j password |
| `--neo4j-database` | `neo4j` | Neo4j database name |

Opens a web UI at `http://localhost:8080` with:
- Hybrid search (BM25 + graph relevance)
- Security overview (input sources, sinks, taint paths)
- Clusters visualization
- Node detail panel with callers/callees

---

### `skills` ⭐ NEW

Generate AI agent skill files based on graph analysis.

```bash
archgraph skills REPO_PATH [OPTIONS]
```

Generates skill files in `.archgraph/skills/`:
- `OVERVIEW.md` — Graph statistics, most-called functions, query templates
- `SECURITY.md` — Input sources, dangerous sinks, taint paths, CVEs
- `IMPACT.md` — Impact analysis guidelines, risk assessment matrix
- `CLUSTER_*.md` — Per-cluster files with member functions

---

### `repos` ⭐ NEW

List all registered repositories.

```bash
archgraph repos [--format table|json]
```

Shows all indexed repositories with their paths, languages, and statistics.

---

### `impact` ⭐ NEW

Analyze blast radius of a function symbol.

```bash
archgraph impact SYMBOL_ID [OPTIONS]
```

**Arguments:**
- `SYMBOL_ID` — Function node ID (e.g., `func:src/auth.c:validate:42`)

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-d, --direction` | `upstream` | Direction: `upstream` (callers), `downstream` (callees), `both` |
| `--depth` | `5` | Max traversal depth |
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j bolt URI |

**Example:**

```bash
# What affects this function?
archgraph impact "func:src/main.c:main:1" --direction upstream

# What does this function affect?
archgraph impact "func:src/api.c:handle:42" --direction downstream

# Both directions
archgraph impact "func:src/auth.c:validate:10" --direction both --depth 8
```

---

### `export` ⭐ NEW

Export code graph to JSON, GraphML, or CSV format.

```bash
archgraph export REPO_PATH [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `json` | Export format: `json`, `graphml`, `csv` |
| `-o, --output` | auto | Output file/directory path |
| `-l, --languages` | `auto` | Languages (auto=detect) |
| `-w, --workers` | `0` | Worker threads |

**Examples:**

```bash
# Export as JSON
archgraph export /path/to/repo

# Export as GraphML (for Gephi, yEd)
archgraph export /path/to/repo --format graphml -o graph.graphml

# Export as CSV (nodes.csv + edges.csv)
archgraph export /path/to/repo --format csv -o output_dir/
```

---

### `report` ⭐ NEW

Generate a single-file HTML security report.

```bash
archgraph report REPO_PATH [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `-o, --output` | `archgraph_report.html` | Output HTML file path |
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j bolt URI |

**Example:**

```bash
# Generate report
archgraph report /path/to/repo

# Custom output path
archgraph report /path/to/repo -o security_report.html
```

The report includes:
- Graph statistics
- High risk functions (score > 50)
- Input sources and dangerous sinks
- Taint paths (input → sink)
- Vulnerabilities (CVEs)
- Clusters and processes

---

## Environment Variables

All Neo4j options can be set via environment variables:

| Variable | Default |
|----------|---------|
| `ARCHGRAPH_NEO4J_URI` | `bolt://localhost:7687` |
| `ARCHGRAPH_NEO4J_USER` | `neo4j` |
| `ARCHGRAPH_NEO4J_PASSWORD` | `neo4j` |
| `ARCHGRAPH_NEO4J_DATABASE` | `neo4j` |

---

## Supported Languages

| Language | Extensions | SCIP Indexer | Deep Analysis |
|----------|-----------|-------------|---------------|
| TypeScript | `.ts`, `.tsx` | `@sourcegraph/scip-typescript` (auto) | — |
| JavaScript | `.js`, `.mjs`, `.cjs`, `.jsx` | `@sourcegraph/scip-typescript` (auto) | — |
| Rust | `.rs` | `rust-analyzer` (auto) | tree-sitter deep |
| Go | `.go` | `scip-go` (auto) | tree-sitter deep |
| Java | `.java` | `scip-java` (auto) | tree-sitter deep |
| Kotlin | `.kt`, `.kts` | `scip-java` (auto) | tree-sitter deep (optional) |
| Python | `.py`, `.pyi` | `@sourcegraph/scip-python` (auto) | — |
| C | `.c`, `.h` | — (heuristic fallback) | libclang (CFG, data flow, taint) |
| C++ | `.cpp`, `.cxx`, `.cc`, `.hpp`, `.hxx`, `.hh` | — (heuristic fallback) | libclang |
| Swift | `.swift` | — | tree-sitter deep (optional) |
| Objective-C | `.m`, `.mm` | — | — (optional) |

SCIP indexers are installed automatically on first extraction. They use each language's
own compiler/type-checker for accurate call resolution. Heuristic fallback resolves calls
by name matching when SCIP is unavailable.

### Prerequisites per Language

| SCIP Indexer | User Must Have | Auto-Installed by ArchGraph |
|-------------|---------------|----------------------------|
| `@sourcegraph/scip-typescript` | Node.js + npm | scip-typescript npm package |
| `@sourcegraph/scip-python` | Node.js + npm | scip-python npm package (auto-patched on Windows) |
| `rust-analyzer` | Rust toolchain (rustup) | rust-analyzer component |
| `scip-go` | Go toolchain | scip-go binary |
| `scip-java` | Java (JDK) | coursier + Maven (to `~/.archgraph/tools/`) |

**Note:** For Java/Kotlin on Windows, Go is also needed to compile the Maven exe shim.
ArchGraph auto-downloads coursier and Maven to `~/.archgraph/tools/` — no global install needed.
