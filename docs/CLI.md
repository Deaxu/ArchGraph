# CLI Reference

ArchGraph provides four commands: `extract`, `query`, `stats`, and `schema`.

## `archgraph extract`

Extract a code graph from a repository and import into Neo4j.

```bash
archgraph extract REPO_PATH [OPTIONS]
```

`REPO_PATH` can be a local directory or a git URL (HTTPS/SSH).

### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--languages` | `-l` | `c,cpp,rust,java,go` | Comma-separated list of languages |
| `--workers` | `-w` | `0` | Worker threads (0=auto, 1=sequential) |
| `--branch` | `-b` | | Branch to clone (git URLs only) |
| `--depth` | `-d` | | Shallow clone depth (git URLs only) |
| `--neo4j-uri` | | `bolt://localhost:7687` | Neo4j bolt URI |
| `--neo4j-user` | | `neo4j` | Neo4j username |
| `--neo4j-password` | | `neo4j` | Neo4j password |
| `--neo4j-database` | | `neo4j` | Neo4j database name |
| `--include-git/--no-git` | | `--include-git` | Git history extraction |
| `--include-deps/--no-deps` | | `--include-deps` | Dependency extraction |
| `--include-annotations/--no-annotations` | | `--include-annotations` | Annotation scanning |
| `--include-clang/--no-clang` | | `--no-clang` | Clang deep analysis (C/C++) |
| `--include-deep/--no-deep` | | `--no-deep` | Tree-sitter deep analysis |
| `--include-cve/--no-cve` | | `--no-cve` | CVE enrichment via OSV API |
| `--compile-commands` | | | Path to `compile_commands.json` |
| `--clear-db/--no-clear-db` | | `--no-clear-db` | Clear database before import |
| `--verbose` | `-v` | | Verbose output |

### Examples

```bash
# Local repo, 4 worker threads
archgraph extract /path/to/repo -l c,cpp -w 4

# GitHub URL with branch and shallow clone
archgraph extract https://github.com/madler/zlib -l c,cpp -b develop -d 100

# Full analysis with clang + deep + CVE
archgraph extract /path/to/repo -l c,cpp,rust \
  --include-clang --include-deep --include-cve \
  -w 4 --clear-db -v

# Sequential mode (debugging)
archgraph extract /path/to/repo -l c -w 1 -v
```

## `archgraph query`

Execute a Cypher query against the graph database.

```bash
archgraph query CYPHER [OPTIONS]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--neo4j-uri` | `bolt://localhost:7687` | Neo4j bolt URI |
| `--neo4j-user` | `neo4j` | Neo4j username |
| `--neo4j-password` | `neo4j` | Neo4j password |
| `--neo4j-database` | `neo4j` | Neo4j database name |

### Examples

```bash
archgraph query "MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file LIMIT 10"

archgraph query "MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability) RETURN d.name, v.vuln_id"
```

## `archgraph stats`

Show graph database statistics (node/edge counts per type).

```bash
archgraph stats [--neo4j-uri ...] [--neo4j-user ...] [--neo4j-password ...] [--neo4j-database ...]
```

## `archgraph schema`

Show graph database schema (labels, relationship types, property keys).

```bash
archgraph schema [--neo4j-uri ...] [--neo4j-user ...] [--neo4j-password ...] [--neo4j-database ...]
```
