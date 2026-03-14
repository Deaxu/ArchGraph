"""Agent skills generation — auto-generates security-focused skill files for AI agents."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from archgraph.graph.neo4j_store import Neo4jStore
from archgraph.graph.schema import NodeLabel

logger = logging.getLogger(__name__)


class SkillGenerator:
    """Generates AI agent skill files based on graph analysis."""

    def __init__(self, store: Neo4jStore) -> None:
        self._store = store

    def generate_skills(self, repo_path: Path) -> list[Path]:
        """Generate skill files for the repository.

        Returns list of generated file paths.
        """
        skills_dir = repo_path / ".archgraph" / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)

        generated: list[Path] = []

        # General repo overview skill
        overview_path = self._generate_overview_skill(skills_dir)
        if overview_path:
            generated.append(overview_path)

        # Security-specific skill
        security_path = self._generate_security_skill(skills_dir)
        if security_path:
            generated.append(security_path)

        # Cluster-specific skills
        cluster_paths = self._generate_cluster_skills(skills_dir)
        generated.extend(cluster_paths)

        # Impact analysis skill
        impact_path = self._generate_impact_skill(skills_dir)
        if impact_path:
            generated.append(impact_path)

        logger.info("Generated %d skill files in %s", len(generated), skills_dir)
        return generated

    def _generate_overview_skill(self, skills_dir: Path) -> Path | None:
        """Generate general repository overview skill."""
        try:
            stats = self._store.stats()
            schema = self._store.schema_info()

            node_counts = stats.get("nodes", {})
            edge_counts = stats.get("edges", {})

            # Get top functions by callers (most important)
            top_funcs = self._store.query(
                "MATCH (f:Function)<-[r:CALLS]-() "
                "RETURN f.name AS name, f.file AS file, count(r) AS callers "
                "ORDER BY callers DESC LIMIT 10"
            )

            content = f"""# ArchGraph Repository Overview

This skill helps navigate the codebase using the ArchGraph knowledge graph.

## Graph Statistics

| Node Type | Count |
|-----------|-------|
{chr(10).join(f'| {label} | {count} |' for label, count in sorted(node_counts.items(), key=lambda x: -x[1]))}

| Edge Type | Count |
|-----------|-------|
{chr(10).join(f'| {etype} | {count} |' for etype, count in sorted(edge_counts.items(), key=lambda x: -x[1]))}

## Most Called Functions (Hub Nodes)

These are the most connected functions — changes here have wide impact:

{chr(10).join(f'1. **{f["name"]}** (`{f["file"]}`) — {f["callers"]} callers' for f in top_funcs)}

## How to Query

Use the `query` tool with Cypher:

```cypher
-- Find all functions in a file
MATCH (f:Function {file: "src/auth.c"}) RETURN f.name, f.line_start

-- Find callers of a function
MATCH (caller:Function)-[:CALLS]->(f:Function {name: "validate"})
RETURN caller.name, caller.file

-- Find input-to-sink paths
MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true})
RETURN src.name, sink.name, length(path)
```

## Security Labels

Functions are labeled with security-relevant attributes:
- `is_input_source` — reads external data (recv, read, fetch, ...)
- `is_dangerous_sink` — dangerous operations (memcpy, exec, eval, ...)
- `is_allocator` — memory allocation (malloc, new, alloc, ...)
- `is_crypto` — cryptographic operations
- `is_parser` — parsing/decoding operations
"""
            path = skills_dir / "OVERVIEW.md"
            path.write_text(content)
            return path

        except Exception as e:
            logger.warning("Failed to generate overview skill: %s", e)
            return None

    def _generate_security_skill(self, skills_dir: Path) -> Path | None:
        """Generate security-focused skill."""
        try:
            # Get input sources
            inputs = self._store.query(
                "MATCH (f:Function {is_input_source: true}) "
                "RETURN f.name AS name, f.file AS file LIMIT 20"
            )

            # Get dangerous sinks
            sinks = self._store.query(
                "MATCH (f:Function {is_dangerous_sink: true}) "
                "RETURN f.name AS name, f.file AS file LIMIT 20"
            )

            # Get taint paths
            taint = self._store.query(
                "MATCH path = (src:Function {is_input_source: true})"
                "-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true}) "
                "RETURN src.name AS source, sink.name AS sink, length(path) AS depth "
                "ORDER BY depth LIMIT 10"
            )

            # Get vulnerabilities
            vulns = self._store.query(
                "MATCH (v:Vulnerability) RETURN v.vuln_id AS id, "
                "v.summary AS summary, v.severity AS severity LIMIT 10"
            )

            content = f"""# ArchGraph Security Analysis Skill

Use this skill when working with security-sensitive code.

## Input Sources (Data Enters Here)

{chr(10).join(f'- **{f["name"]}** in `{f["file"]}`' for f in inputs) if inputs else 'No input sources detected.'}

## Dangerous Sinks (Risk Points)

{chr(10).join(f'- **{f["name"]}** in `{f["file"]}`' for f in sinks) if sinks else 'No dangerous sinks detected.'}

## Taint Paths (Input → Sink)

These are paths where external data reaches dangerous operations:

{chr(10).join(f'{i+1}. `{t["source"]}` → `{t["sink"]}` (depth: {t["depth"]})' for i, t in enumerate(taint)) if taint else 'No taint paths detected.'}

## Known Vulnerabilities

{chr(10).join(f'- **{v["id"]}** ({v.get("severity", "unknown")}): {v.get("summary", "N/A")[:100]}' for v in vulns) if vulns else 'No vulnerabilities detected.'}

## Security Query Templates

```cypher
-- Find all functions that handle user input
MATCH (f:Function {is_input_source: true})
RETURN f.name, f.file, f.line_start

-- Trace data flow from input to sink
MATCH path = (src:Function {is_input_source: true})-[:CALLS*1..8]->(sink:Function {is_dangerous_sink: true})
RETURN [n in nodes(path) | n.name] AS call_chain

-- Find security-fix commits
MATCH (sf:SecurityFix)-[:FIXED_BY]->(c:Commit)
RETURN c.hash, c.message, c.date ORDER BY c.date DESC

-- Find dependencies with CVEs
MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability)
RETURN d.name, d.version, v.vuln_id, v.severity
```

## ⚠️ Security Guidelines

When modifying code:
1. **Never trust input sources** — always validate data from recv/read/fetch
2. **Audit sink calls** — check that user data doesn't reach memcpy/exec/eval
3. **Check dependency CVEs** before adding new dependencies
4. **Review taint paths** — any input→sink path is a potential vulnerability
"""
            path = skills_dir / "SECURITY.md"
            path.write_text(content)
            return path

        except Exception as e:
            logger.warning("Failed to generate security skill: %s", e)
            return None

    def _generate_cluster_skills(self, skills_dir: Path) -> list[Path]:
        """Generate skill files for each detected cluster."""
        generated: list[Path] = []

        try:
            clusters = self._store.query(
                "MATCH (c:Cluster) "
                "RETURN c._id AS id, c.name AS name, c.size AS size, c.cohesion AS cohesion "
                "ORDER BY c.size DESC LIMIT 20"
            )

            for cluster in clusters:
                # Get cluster members
                members = self._store.query(
                    "MATCH (f:Function)-[:BELONGS_TO]->(c:Cluster {_id: $id}) "
                    "RETURN f.name AS name, f.file AS file "
                    "ORDER BY f.file, f.name",
                    {"id": cluster["id"]},
                )

                if not members:
                    continue

                # Group by file
                files: dict[str, list[str]] = {}
                for m in members:
                    f = m.get("file", "unknown")
                    files.setdefault(f, []).append(m["name"])

                cluster_name = cluster.get("name", "unknown").replace(" ", "_")
                content = f"""# Cluster: {cluster.get('name', 'Unknown')}

**Size:** {cluster.get('size', 0)} functions | **Cohesion:** {cluster.get('cohesion', 0)}

## Files in this Cluster

{chr(10).join(f'### `{f}`{chr(10)}{chr(10).join("- " + fn for fn in funcs)}' for f, funcs in sorted(files.items()))}

## Key Relationships

This cluster represents a functional unit. Functions within it are tightly coupled
through call relationships (cohesion score: {cluster.get('cohesion', 0)}).

## Guidelines

- Changes within this cluster should be tested together
- Watch for side effects when modifying shared functions
- Check cross-cluster dependencies before refactoring
"""
                path = skills_dir / f"CLUSTER_{cluster_name}.md"
                path.write_text(content)
                generated.append(path)

        except Exception as e:
            logger.warning("Failed to generate cluster skills: %s", e)

        return generated

    def _generate_impact_skill(self, skills_dir: Path) -> Path | None:
        """Generate impact analysis guidance skill."""
        try:
            content = """# ArchGraph Impact Analysis Skill

Use this skill before making changes to understand blast radius.

## Before Modifying Code

1. **Check impact**: Use the `impact` tool to see what depends on the function
2. **Check security**: Is the function an input source or dangerous sink?
3. **Check cluster**: What cluster does it belong to? Are there cross-cluster deps?
4. **Check processes**: What execution flows include this function?

## Query Templates

```cypher
-- Find immediate callers (depth 1)
MATCH (caller:Function)-[:CALLS]->(target:Function {name: "foo"})
RETURN caller.name, caller.file

-- Find transitive callers (depth 1-5)
MATCH path = (caller:Function)-[:CALLS*1..5]->(target:Function {name: "foo"})
RETURN caller.name, length(path) AS depth ORDER BY depth

-- Find functions affected by file change
MATCH (f:Function {file: "src/changed.c"})-[:BELONGS_TO]->(c:Cluster)
MATCH (other:Function)-[:BELONGS_TO]->(c)
WHERE other.file <> "src/changed.c"
RETURN other.name, other.file

-- Find security impact of changes
MATCH (changed:Function {file: "src/api.c"})-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true})
RETURN sink.name, sink.file
```

## Risk Assessment Matrix

| Factor | Risk Level |
|--------|------------|
| Function is input source + changes reach sink | CRITICAL |
| Function is dangerous sink | HIGH |
| Function has >10 callers | MEDIUM |
| Function in cluster with >5 members | LOW |
| Isolated function with no callers | MINIMAL |
"""
            path = skills_dir / "IMPACT.md"
            path.write_text(content)
            return path

        except Exception as e:
            logger.warning("Failed to generate impact skill: %s", e)
            return None
