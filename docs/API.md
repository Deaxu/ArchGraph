# Python API Reference

Programmatic access to ArchGraph via the `ArchGraph` class.

## Quick Start

```python
from archgraph import ArchGraph

with ArchGraph() as ag:
    result = ag.extract("/path/to/repo")
    print(f"{result['nodes']} nodes, {result['edges']} edges")

    funcs = ag.search(name="main", type="function")
    calls = ag.search_calls(target="main", resolved_only=True)
    source = ag.source(funcs[0]["id"])
    ctx = ag.context(funcs[0]["id"])
    impact = ag.impact(funcs[0]["id"], direction="downstream")
```

## Constructor

```python
ArchGraph(
    neo4j_uri: str = "bolt://localhost:7687",
    neo4j_user: str = "neo4j",
    neo4j_password: str = "archgraph",
    neo4j_database: str = "neo4j",
)
```

Supports context manager (`with` statement). Call `close()` explicitly if not using `with`.

---

## Methods

### `extract`

Extract code graph from a repository and import into Neo4j.

```python
ag.extract(
    repo: str,                          # Git URL or local path
    languages: str = "auto",            # Comma-separated or "auto"
    clear_db: bool = False,             # Clear graph before import
    include_body: bool = True,          # Store source code in nodes
    include_git: bool = True,           # Git history extraction
    include_deps: bool = True,          # Dependency extraction
    include_annotations: bool = True,   # TODO/HACK/FIXME scanning
    include_security_labels: bool = True,  # Automatic security labeling
    include_deep: bool = True,          # CFG, data flow, taint analysis
    include_clang: bool = True,         # libclang C/C++ analysis (skipped if not installed)
    include_cve: bool = False,          # CVE scanning via OSV API
    include_scip: bool = True,          # SCIP compiler-backed call resolution
    include_clustering: bool = False,   # Community detection
    include_process: bool = False,      # Execution flow tracing
    workers: int = 0,                   # Threads (0=auto, 1=sequential)
    incremental: bool = False,          # Only re-extract changed files
    max_body_size: int = 51_200,        # Max body bytes per node
    compile_commands: Path | None = None,  # compile_commands.json for clang
    branch: str | None = None,          # Branch to clone (git URLs)
    depth: int | None = 1,              # Clone depth (git URLs)
) -> dict[str, Any]
```

**Returns:**

```python
{
    "status": "success",
    "repo": "/path/to/repo",
    "languages": ["typescript", "javascript"],
    "nodes": 1234,
    "edges": 5678,
    "node_types": {"Function": 800, "File": 50, ...},
    "edge_types": {"CALLS": 3000, "CONTAINS": 1200, ...},
    "extraction_time": "12.3s",
    "import_time": "2.1s",
    "nodes_imported": 1234,
    "edges_imported": 5678,
    "warnings": []  # optional
}
```

**Examples:**

```python
# Local repo
ag.extract("/path/to/repo", languages="rust,go")

# Git URL with shallow clone
ag.extract("https://github.com/user/project", branch="main", depth=1)

# Full security analysis
ag.extract("/path/to/repo", include_cve=True, include_clustering=True)

# Incremental re-extraction
ag.extract("/path/to/repo", incremental=True)
```

---

### `query`

Execute a raw Cypher query.

```python
ag.query(
    cypher: str,                        # Cypher query string
    params: dict[str, Any] | None = None,  # Query parameters
) -> list[dict[str, Any]]
```

**Examples:**

```python
# Find all input sources
ag.query("MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file")

# Parameterized query
ag.query(
    "MATCH (f:Function) WHERE f.name = $name RETURN f._id, f.file",
    params={"name": "validate"}
)
```

---

### `search`

Search symbols by name, type, or file pattern. No Cypher needed.

```python
ag.search(
    name: str = "",                     # Symbol name (* wildcards supported)
    type: str = "",                     # function, class, struct, interface, enum, module, file
    file_pattern: str = "",             # File path pattern (* wildcards)
    limit: int = 20,                    # Max results
) -> list[dict[str, Any]]
```

**Returns** list of `{id, name, labels, file, line}`.

```python
ag.search(name="*Handler", type="class")
ag.search(file_pattern="*auth*", type="function")
```

---

### `search_calls`

Search call relationships between functions.

```python
ag.search_calls(
    caller: str = "",                   # Caller name (partial match)
    target: str = "",                   # Target name (partial match)
    file: str = "",                     # File path filter (partial match)
    resolved_only: bool = False,        # Only resolved calls
    source: str = "any",               # "scip", "heuristic", or "any"
    max_depth: int = 1,                 # 1=direct, >1=transitive chains
    limit: int = 20,                    # Max results
) -> list[dict[str, Any]]
```

**Returns** list of `{caller, caller_file, target, target_file, resolved, source}`.

```python
# Who calls validate?
ag.search_calls(target="validate", resolved_only=True)

# Transitive call chain from main
ag.search_calls(caller="main", max_depth=3, source="scip")
```

---

### `source`

Get source code of a symbol by its node ID.

```python
ag.source(symbol_id: str) -> dict[str, Any] | None
```

**Returns** `{body, name, file, line_start, line_end, body_lines, body_truncated}` or `None`.

```python
src = ag.source("func:src/auth.c:validate:42")
print(src["body"])
```

---

### `context`

Get 360-degree view of a symbol: properties, callers, callees, cluster, security labels.

```python
ag.context(symbol_id: str) -> dict[str, Any]
```

**Returns:**

```python
{
    "symbol": {"id": "...", "properties": {...}},
    "callers": [{"id": "...", "name": "...", "file": "...", "resolved": True, "source": "scip"}],
    "callees": [...],
    "cluster": {"id": "cluster:0", "name": "auth_cluster", "cohesion": 0.89} | None,
    "security_labels": {"is_input_source": True, ...}
}
```

---

### `impact`

Analyze blast radius of a function.

```python
ag.impact(
    symbol_id: str,                     # Function node ID
    direction: str = "downstream",      # "upstream", "downstream", or "both"
    max_depth: int = 5,                 # Max traversal depth
) -> dict[str, Any]
```

**Returns** affected functions, transitive impact, security flags, confidence score.

```python
result = ag.impact("func:src/auth.c:validate:42", direction="both", max_depth=8)
print(f"{result['total_affected']} affected functions")
```

---

### `stats`

Get graph statistics.

```python
ag.stats() -> dict[str, Any]
```

**Returns:**

```python
{
    "graph_stats": {"nodes": 1234, "edges": 5678, ...},
    "clusters": 5,
    "processes": 3
}
```

---

### `detect_changes`

Analyze impact of changed files on the codebase.

```python
ag.detect_changes(
    changed_files: list[str],           # List of changed file paths
) -> dict[str, Any]
```

Returns affected clusters, processes, security risks, and risk level.

```python
ag.detect_changes(["src/auth.ts", "src/api.ts"])
```

---

### `find_vulnerabilities`

Find known CVE vulnerabilities in project dependencies.

```python
ag.find_vulnerabilities(
    severity: str | None = None,        # "CRITICAL", "HIGH", "MEDIUM", "LOW"
) -> list[dict[str, Any]]
```

**Returns** list of `{dependency, version, vuln_id, summary, severity}`.

```python
ag.find_vulnerabilities(severity="CRITICAL")
```

---

### `repos`

List all extracted repositories.

```python
ag.repos() -> list[dict[str, Any]]
```

---

### `close`

Close the Neo4j connection.

```python
ag.close() -> None
```

Called automatically when using `with` statement.
