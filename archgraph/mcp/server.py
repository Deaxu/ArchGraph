"""MCP server — Model Context Protocol integration for AI agents."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from archgraph.graph.neo4j_store import Neo4jStore
from archgraph.tool.impact import ImpactAnalyzer

logger = logging.getLogger(__name__)

# MCP Tool descriptions
TOOLS = [
    {
        "name": "query",
        "description": "Execute a Cypher query against the ArchGraph code knowledge graph",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cypher": {
                    "type": "string",
                    "description": "Cypher query string",
                },
                "params": {
                    "type": "object",
                    "description": "Optional query parameters",
                },
            },
            "required": ["cypher"],
        },
    },
    {
        "name": "impact",
        "description": "Analyze blast radius of a function — what it affects or what affects it",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol_id": {
                    "type": "string",
                    "description": "Function node ID (e.g. 'func:src/auth.c:validate:42')",
                },
                "direction": {
                    "type": "string",
                    "enum": ["upstream", "downstream", "both"],
                    "description": "upstream=callers, downstream=callees",
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum traversal depth (default: 5)",
                },
            },
            "required": ["symbol_id"],
        },
    },
    {
        "name": "context",
        "description": "Get 360-degree view of a symbol — its properties, callers, callees, cluster, and security labels",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol_id": {
                    "type": "string",
                    "description": "Symbol node ID",
                },
            },
            "required": ["symbol_id"],
        },
    },
    {
        "name": "detect_changes",
        "description": "Analyze impact of changed files on the codebase",
        "inputSchema": {
            "type": "object",
            "properties": {
                "changed_files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of changed file paths",
                },
            },
            "required": ["changed_files"],
        },
    },
    {
        "name": "find_vulnerabilities",
        "description": "Find known CVE vulnerabilities affecting project dependencies",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)",
                },
            },
        },
    },
    {
        "name": "cypher",
        "description": "Execute raw Cypher query (alias for query tool)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Cypher query string",
                },
                "params": {
                    "type": "object",
                    "description": "Optional parameters",
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "stats",
        "description": "Get graph statistics — node/edge counts, clusters, processes",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "source",
        "description": "Get source code of a function, class, struct, or other symbol",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol_id": {
                    "type": "string",
                    "description": "Symbol node ID (e.g. 'func:src/auth.c:validate:42')",
                },
            },
            "required": ["symbol_id"],
        },
    },
]

# MCP Resources
RESOURCES = [
    {
        "uri": "archgraph://schema",
        "name": "Graph Schema",
        "description": "Node labels, edge types, and property keys",
        "mimeType": "application/json",
    },
    {
        "uri": "archgraph://security",
        "name": "Security Overview",
        "description": "Input sources, dangerous sinks, and taint paths",
        "mimeType": "application/json",
    },
    {
        "uri": "archgraph://clusters",
        "name": "Functional Clusters",
        "description": "Detected communities and their cohesion scores",
        "mimeType": "application/json",
    },
    {
        "uri": "archgraph://processes",
        "name": "Execution Processes",
        "description": "Traced execution flows from entry points",
        "mimeType": "application/json",
    },
]



import hashlib
import time
from functools import lru_cache

class _ToolCache:
    """Simple TTL cache for MCP tool results."""
    
    def __init__(self, ttl: int = 60, maxsize: int = 128):
        self._ttl = ttl
        self._cache: dict[str, tuple[float, Any]] = {}
        self._maxsize = maxsize
    
    def _make_key(self, name: str, arguments: dict[str, Any]) -> str:
        raw = f"{name}:{json.dumps(arguments, sort_keys=True)}"
        return hashlib.md5(raw.encode()).hexdigest()
    
    def get(self, name: str, arguments: dict[str, Any]) -> Any | None:
        key = self._make_key(name, arguments)
        if key in self._cache:
            ts, value = self._cache[key]
            if time.time() - ts < self._ttl:
                return value
            del self._cache[key]
        return None
    
    def set(self, name: str, arguments: dict[str, Any], value: Any) -> None:
        if len(self._cache) >= self._maxsize:
            # Evict oldest
            oldest_key = min(self._cache, key=lambda k: self._cache[k][0])
            del self._cache[oldest_key]
        key = self._make_key(name, arguments)
        self._cache[key] = (time.time(), value)

class ArchGraphMCP:
    """ArchGraph MCP server implementation."""

    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "archgraph",
        neo4j_database: str = "neo4j",
    ) -> None:
        self._store = Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database)
        self._impact = ImpactAnalyzer(self._store)
        self._cache = _ToolCache(ttl=60)

    def connect(self) -> None:
        self._store.connect()

    def close(self) -> None:
        self._store.close()

    async def handle_tool_call(self, name: str, arguments: dict[str, Any]) -> Any:
        """Handle an MCP tool call."""
        # Check cache
        if name not in ("detect_changes",):
            cached = self._cache.get(name, arguments)
            if cached is not None:
                return cached
        
        result = None
        try:
            if name == "query" or name == "cypher":
                cypher = arguments.get("cypher") or arguments.get("query", "")
                params = arguments.get("params", {})
                result = self._store.query(cypher, params)

            elif name == "impact":
                symbol_id = arguments["symbol_id"]
                direction = arguments.get("direction", "upstream")
                max_depth = arguments.get("max_depth", 5)
                result = self._impact.analyze_impact(symbol_id, direction, max_depth)

            elif name == "context":
                result = self._get_context(arguments["symbol_id"])

            elif name == "detect_changes":
                result = self._impact.analyze_change_impact(arguments["changed_files"])

            elif name == "find_vulnerabilities":
                severity = arguments.get("severity")
                result = self._find_vulnerabilities(severity)

            elif name == "stats":
                result = self._get_stats()

            elif name == "source":
                symbol_id = arguments["symbol_id"]
                source_result = self._store.get_source(symbol_id)
                if source_result:
                    result = source_result
                else:
                    result = {"error": f"Symbol not found or has no body: {symbol_id}"}

            else:
                result = {"error": f"Unknown tool: {name}"}

        except Exception as e:
            logger.exception("Tool call failed: %s", name)
            result = {"error": str(e)}
        
        # Cache successful results
        if result is not None and not isinstance(result, dict) or "error" not in result:
            self._cache.set(name, arguments, result)
        
        return result

    async def handle_resource_read(self, uri: str) -> Any:
        """Handle an MCP resource read."""
        try:
            if uri == "archgraph://schema":
                return self._store.schema_info()

            elif uri == "archgraph://security":
                return self._get_security_overview()

            elif uri == "archgraph://clusters":
                return self._store.query(
                    "MATCH (c:Cluster) RETURN c._id AS id, c.name AS name, "
                    "c.size AS size, c.cohesion AS cohesion ORDER BY c.size DESC"
                )

            elif uri == "archgraph://processes":
                return self._store.query(
                    "MATCH (p:Process) RETURN p._id AS id, p.name AS name, "
                    "p.type AS type, p.step_count AS steps ORDER BY p.step_count DESC"
                )

            else:
                return {"error": f"Unknown resource: {uri}"}

        except Exception as e:
            logger.exception("Resource read failed: %s", uri)
            return {"error": str(e)}

    def _get_context(self, symbol_id: str) -> dict[str, Any]:
        """Get 360-degree context of a symbol."""
        # Get symbol properties
        symbol = self._store.query(
            "MATCH (n:_Node {_id: $id}) RETURN properties(n) AS props",
            {"id": symbol_id},
        )

        if not symbol:
            return {"error": f"Symbol not found: {symbol_id}"}

        props = symbol[0].get("props", {})
        props.pop("body", None)  # body is served via the source tool

        # Get callers (upstream)
        callers = self._store.query(
            "MATCH (f:Function)-[:CALLS]->(n:_Node {_id: $id}) "
            "RETURN f._id AS id, f.name AS name, f.file AS file",
            {"id": symbol_id},
        )

        # Get callees (downstream)
        callees = self._store.query(
            "MATCH (n:_Node {_id: $id})-[:CALLS]->(f:Function) "
            "RETURN f._id AS id, f.name AS name, f.file AS file",
            {"id": symbol_id},
        )

        # Get cluster membership
        cluster = self._store.query(
            "MATCH (n:_Node {_id: $id})-[:BELONGS_TO]->(c:Cluster) "
            "RETURN c._id AS id, c.name AS name, c.cohesion AS cohesion",
            {"id": symbol_id},
        )

        # Get process participation
        processes = self._store.query(
            "MATCH (n:_Node {_id: $id})-[:PARTICIPATES_IN]->(p:Process) "
            "RETURN p._id AS id, p.name AS name, p.type AS type",
            {"id": symbol_id},
        )

        # Security labels
        security = {}
        for key in [
            "is_input_source", "is_dangerous_sink", "is_allocator",
            "is_crypto", "is_parser", "touches_unsafe",
        ]:
            if props.get(key):
                security[key] = True

        return {
            "symbol": {"id": symbol_id, "properties": props},
            "callers": callers,
            "callees": callees,
            "cluster": cluster[0] if cluster else None,
            "processes": processes,
            "security_labels": security,
        }

    def _get_security_overview(self) -> dict[str, Any]:
        """Get security overview of the codebase."""
        input_sources = self._store.query(
            "MATCH (f:Function {is_input_source: true}) "
            "RETURN f._id AS id, f.name AS name, f.file AS file "
            "ORDER BY f.file, f.name LIMIT 100"
        )

        dangerous_sinks = self._store.query(
            "MATCH (f:Function {is_dangerous_sink: true}) "
            "RETURN f._id AS id, f.name AS name, f.file AS file "
            "ORDER BY f.file, f.name LIMIT 100"
        )

        # Taint paths: input → sink
        taint_paths = self._store.query(
            "MATCH path = (src:Function {is_input_source: true})"
            "-[:CALLS*1..5]->(sink:Function {is_dangerous_sink: true}) "
            "RETURN src.name AS source, sink.name AS sink, "
            "length(path) AS path_length "
            "ORDER BY path_length LIMIT 50"
        )

        vulnerabilities = self._store.query(
            "MATCH (v:Vulnerability) "
            "RETURN v.vuln_id AS id, v.summary AS summary, v.severity AS severity "
            "ORDER BY v.severity LIMIT 50"
        )

        return {
            "input_sources": input_sources,
            "dangerous_sinks": dangerous_sinks,
            "taint_paths": taint_paths,
            "vulnerabilities": vulnerabilities,
        }

    def _find_vulnerabilities(self, severity: str | None = None) -> list[dict[str, Any]]:
        """Find vulnerabilities with optional severity filter."""
        cypher = (
            "MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability) "
            "RETURN d.name AS dependency, d.version AS version, "
            "v.vuln_id AS vuln_id, v.summary AS summary, v.severity AS severity"
        )
        results = self._store.query(cypher)
        if severity:
            results = [r for r in results if severity.upper() in (r.get("severity") or "").upper()]
        return results

    def _get_stats(self) -> dict[str, Any]:
        """Get graph statistics."""
        db_stats = self._store.stats()

        # Additional stats
        cluster_count = self._store.query(
            "MATCH (c:Cluster) RETURN count(c) AS count"
        )
        process_count = self._store.query(
            "MATCH (p:Process) RETURN count(p) AS count"
        )

        return {
            "graph_stats": db_stats,
            "clusters": cluster_count[0]["count"] if cluster_count else 0,
            "processes": process_count[0]["count"] if process_count else 0,
        }


def create_mcp_server(**kwargs: Any) -> ArchGraphMCP:
    """Factory function for creating MCP server instance."""
    return ArchGraphMCP(**kwargs)


async def run_mcp_server(**kwargs: Any) -> None:
    """Run the MCP server (stdio transport)."""
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp import types
    except ImportError:
        logger.error("MCP package not installed. Run: pip install mcp")
        return

    arch = ArchGraphMCP(**kwargs)
    arch.connect()

    server = Server("archgraph")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [types.Tool(**t) for t in TOOLS]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
        result = await arch.handle_tool_call(name, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    @server.list_resources()
    async def list_resources() -> list[types.Resource]:
        return [types.Resource(**r) for r in RESOURCES]

    @server.read_resource()
    async def read_resource(uri: str) -> str:
        result = await arch.handle_resource_read(uri)
        return json.dumps(result, indent=2)

    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    finally:
        arch.close()
