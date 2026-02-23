# Agent Integration

ArchGraph provides an `ArchGraphTool` class for integration with rlm-agent or any LLM-based agent framework.

## Design Philosophy

The tool exposes a **single `query()` method**. The full graph schema (node labels, edge types, properties, ID format) is embedded in `tool.description`, so the agent has the schema in its context window and can write Cypher autonomously without discovery calls.

## Usage

```python
from archgraph.tool.archgraph_tool import ArchGraphTool

with ArchGraphTool(neo4j_uri="bolt://localhost:7687") as tool:
    # Raw Cypher query
    results = tool.query(
        "MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file"
    )

    # Parameterized query
    results = tool.query(
        "MATCH (f:Function {name: $name}) RETURN f",
        params={"name": "parse_data"}
    )

    # Convenience method: find vulnerabilities
    vulns = tool.find_vulnerabilities(severity="CRITICAL")
```

## API Reference

### `ArchGraphTool`

```python
class ArchGraphTool:
    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "neo4j",
        neo4j_database: str = "neo4j",
    ) -> None: ...

    def query(
        self,
        cypher: str,
        params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]: ...

    def find_vulnerabilities(
        self,
        severity: str | None = None,
    ) -> list[dict[str, Any]]: ...
```

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `name` | `str` | `"archgraph"` |
| `description` | `str` | Full schema documentation for agent context |

### Lifecycle

```python
tool = ArchGraphTool(neo4j_uri="bolt://localhost:7687")
tool.connect()    # or use context manager
# ... queries ...
tool.close()      # or tool.cleanup() for rlm-agent
```

## rlm-agent Entry Point

The tool provides a `create_tool()` factory function for entry-point registration:

```python
# pyproject.toml (when rlm-agent dependency is available)
[project.entry-points."rlm_agent.tools"]
archgraph = "archgraph.tool.archgraph_tool:create_tool"
```

## Example Agent Queries

### Attack Surface Analysis

```cypher
-- Find all input sources
MATCH (f:Function {is_input_source: true})
RETURN f.name, f.file, f.line_start

-- Find input-to-sink paths
MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true})
RETURN [n IN nodes(path) | n.name] AS chain, length(path) AS depth
```

### Dependency Analysis

```cypher
-- Find all dependencies with versions
MATCH (m:Module)-[:DEPENDS_ON]->(d:Dependency)
RETURN m.name AS module, d.name, d.version, d.source

-- Find vulnerable dependencies
MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN d.name, d.version, v.vuln_id, v.summary
```

### Code Quality

```cypher
-- High-churn files with TODOs
MATCH (f:File)-[:HAS_ANNOTATION]->(a:Annotation {type: "TODO"})
WHERE f.churn_count > 5
RETURN f.path, a.text, f.churn_count
ORDER BY f.churn_count DESC

-- Functions with most callers
MATCH (caller:Function)-[:CALLS]->(f:Function)
WHERE NOT f._id STARTS WITH "funcref:"
RETURN f.name, f.file, count(caller) AS callers
ORDER BY callers DESC LIMIT 20
```

### Git Forensics

```cypher
-- Largest commits
MATCH (c:Commit)
WHERE c.total_insertions > 100
RETURN c.message, c.total_insertions, c.total_deletions, c.date
ORDER BY c.total_insertions DESC LIMIT 10

-- Per-file stats in a commit
MATCH (f:File)-[m:MODIFIED_IN]->(c:Commit {hash: $hash})
RETURN f.path, m.lines_added, m.lines_deleted

-- Release timeline
MATCH (c:Commit)-[:TAGGED_AS]->(t:Tag)
RETURN t.name, c.total_insertions, c.total_deletions, c.date
ORDER BY c.date DESC
```
