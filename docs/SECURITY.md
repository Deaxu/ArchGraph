# Security Analysis

ArchGraph provides automated security labeling, taint tracking, CVE enrichment, and AI agent integration for security auditing.

## Supported Languages

Security analysis works across all 11 supported languages: C, C++, Rust, Java, Kotlin, Go, TypeScript, JavaScript, Python, Swift, Objective-C.

SCIP-backed call resolution (TS/JS, Python, Rust, Go, Java/Kotlin) uses compiler-level type information for accurate call chain tracking between security-critical functions. C/C++ uses heuristic resolution with libclang deep analysis for taint tracking.

## Automatic Security Labels

Functions are automatically labeled based on name matching against curated pattern sets defined in `config.py`:

| Label | Description | Example Functions |
|-------|-------------|-------------------|
| `is_input_source` | Reads external data | recv, read, fgets, getenv, stdin, fetch, getParameter |
| `is_dangerous_sink` | Potentially unsafe operations | memcpy, strcpy, system, eval, innerHTML, exec |
| `is_allocator` | Memory allocation/deallocation | malloc, free, new, delete, Box::new, make |
| `is_crypto` | Cryptographic operations | encrypt, SHA256, EVP_EncryptInit, hmac.New |
| `is_parser` | Data parsing/deserialization | parse, JSON.parse, json.Unmarshal, deserialize |
| `is_unsafe` | Unsafe code patterns | unsafe blocks (Rust), pointer arithmetic (C) |

## Taint Tracking

When deep analysis is enabled (`--include-clang` or `--include-deep`), ArchGraph performs intra-procedural taint propagation:

1. Variables assigned from `INPUT_SOURCE` calls are marked tainted
2. Function parameters are conservatively marked tainted
3. Variables assigned from tainted variables inherit the taint
4. If a tainted variable flows into a `DANGEROUS_SINK`, a `TAINTS` edge is created

## Security-Focused Clustering

When `--include-clustering` is enabled, functions are grouped into functional communities. This helps identify security-critical modules:

```cypher
-- Find clusters with dangerous sinks
MATCH (f:Function {is_dangerous_sink: true})-[:BELONGS_TO]->(c:Cluster)
RETURN c.name, c.cohesion, count(f) AS sinks
ORDER BY sinks DESC

-- Find clusters that touch both input and sink
MATCH (input:Function {is_input_source: true})-[:BELONGS_TO]->(c:Cluster)
MATCH (sink:Function {is_dangerous_sink: true})-[:BELONGS_TO]->(c)
RETURN c.name, collect(DISTINCT input.name) AS inputs, collect(DISTINCT sink.name) AS sinks
```

## Process Tracing for Security

When `--include-process` is enabled, execution flows are traced from entry points. Processes are classified by security impact:

| Type | Description |
|------|-------------|
| `data_flow` | Touches both input sources AND dangerous sinks ⚠️ |
| `input_handler` | Touches input sources only |
| `sink_caller` | Touches dangerous sinks only |
| `computation` | Neither input nor sink |

```cypher
-- Find all data_flow processes (input → sink)
MATCH (p:Process {type: "data_flow"})
MATCH (f:Function)-[:PARTICIPATES_IN]->(p)
RETURN p.name, p.entry_point, collect(f.name) AS functions

-- Find security-critical execution paths
MATCH (p:Process {type: "data_flow"})
MATCH (f:Function {is_dangerous_sink: true})-[:PARTICIPATES_IN]->(p)
RETURN p.name, f.name AS sink_function, p.step_count
```

## CVE Enrichment

When enabled (`--include-cve`), ArchGraph queries the [OSV API](https://osv.dev) for known vulnerabilities in extracted dependencies.

### How It Works

1. Dependency nodes are collected (name, version, source file)
2. Source file is mapped to OSV ecosystem (e.g., `Cargo.toml` -> `crates.io`)
3. Batch query sent to `https://api.osv.dev/v1/querybatch`
4. Results create `Vulnerability` nodes linked by `AFFECTED_BY` edges

### Supported Ecosystems

| Manifest File | OSV Ecosystem |
|---------------|---------------|
| Cargo.toml | crates.io |
| package.json | npm |
| go.mod | Go |
| build.gradle | Maven |
| requirements.txt | PyPI |
| setup.py / pyproject.toml | PyPI |
| Podfile | CocoaPods |
| conanfile.txt | ConanCenter |
| Package.swift | SwiftURL |

### Vulnerability Node Properties

| Property | Description |
|----------|-------------|
| `vuln_id` | Vulnerability identifier (CVE-xxxx, GHSA-xxxx, PYSEC-xxxx) |
| `summary` | Brief description |
| `severity` | CVSS score or severity string |
| `aliases` | Comma-separated list of aliases (e.g., CVE, GHSA cross-references) |

## Source Code Review

With body storage enabled (default), function and class source code is stored in graph nodes. Use the `source` tool or CLI to review security-critical code:

```bash
# Search for dangerous sinks
archgraph search --name "exec*" --type function

# Get source code via MCP/API
source({symbol_id: "func:src/api.py:execute_query:42"})
```

## Impact Analysis

Use the `impact` command to understand blast radius before making changes:

```bash
# What depends on this function?
archgraph impact "func:src/auth.c:validate:42" --direction upstream

# Security impact of changes
archgraph impact "func:src/net.c:recv_data:10" --direction both --depth 8
```

Or via MCP/Python API for AI agents:
```python
ag.impact("func:src/api.c:handle:42", direction="both", max_depth=5)
ag.find_vulnerabilities(severity="CRITICAL")
ag.detect_changes(["src/auth.py", "src/api.py"])
```

## Example Queries

```cypher
-- Find input-to-sink paths (potential vulnerabilities)
MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true})
RETURN src.name AS source, sink.name AS sink, length(path) AS depth,
       [n IN nodes(path) | n.name] AS chain

-- Find tainted data flows
MATCH (a)-[t:TAINTS]->(b)
RETURN a._id AS source, b._id AS sink, t.via_function, t.via_variable, t.file

-- High-churn files containing dangerous sinks
MATCH (f:File)-[:CONTAINS]->(fn:Function {is_dangerous_sink: true})
WHERE f.churn_count > 10
RETURN f.path, fn.name, f.churn_count
ORDER BY f.churn_count DESC

-- Which authors touched dangerous sink files most?
MATCH (f:File)-[:CONTAINS]->(fn:Function {is_dangerous_sink: true})
MATCH (f)-[:MODIFIED_IN]->(c:Commit)-[:AUTHORED_BY]->(a:Author)
RETURN a.name, count(DISTINCT c) AS commits, collect(DISTINCT fn.name)[..5] AS sinks
ORDER BY commits DESC

-- Security fixes and affected files
MATCH (sf:SecurityFix)-[:AFFECTS]->(f:File)
MATCH (sf)-[:FIXED_BY]->(c:Commit)-[:AUTHORED_BY]->(a:Author)
RETURN sf.description, f.path, a.name, c.date

-- Find vulnerable dependencies
MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN d.name, d.version, v.vuln_id, v.summary, v.severity
ORDER BY v.severity DESC

-- Files depending on vulnerable packages
MATCH (m:Module)-[:DEPENDS_ON]->(d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN m.name AS module, d.name AS dependency, v.vuln_id, v.summary

-- Crypto functions that are also input sources (risky)
MATCH (f:Function {is_crypto: true, is_input_source: true})
RETURN f.name, f.file

-- Memory allocations in high-churn files
MATCH (f:File)-[:CONTAINS]->(fn:Function {is_allocator: true})
WHERE f.churn_count > 5
RETURN f.path, fn.name, f.churn_count
ORDER BY f.churn_count DESC
```
