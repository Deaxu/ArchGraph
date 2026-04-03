"""Python API for ArchGraph — programmatic access to code graph extraction and querying."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from archgraph.config import ExtractConfig
from archgraph.graph.builder import GraphBuilder
from archgraph.graph.neo4j_store import Neo4jStore

logger = logging.getLogger(__name__)


class ArchGraph:
    """High-level Python API for ArchGraph.

    Usage:
        ag = ArchGraph()
        result = ag.extract("https://github.com/user/repo")
        print(result["nodes"], "nodes extracted")

        results = ag.query("MATCH (f:Function) RETURN f.name LIMIT 5")
        symbols = ag.search(name="main", type="function")
        calls = ag.search_calls(caller="main")
        source = ag.source("func:src/main.ts:main:1")
    """

    def __init__(
        self,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_user: str = "neo4j",
        neo4j_password: str = "archgraph",
        neo4j_database: str = "neo4j",
    ) -> None:
        self._uri = neo4j_uri
        self._user = neo4j_user
        self._password = neo4j_password
        self._database = neo4j_database
        self._store: Neo4jStore | None = None

    def _get_store(self) -> Neo4jStore:
        if self._store is None:
            self._store = Neo4jStore(self._uri, self._user, self._password, self._database)
            self._store.connect()
        return self._store

    def close(self) -> None:
        if self._store:
            self._store.close()
            self._store = None

    def __enter__(self) -> ArchGraph:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ── Extract ───────────────────────────────────────────────────────────

    def extract(
        self,
        repo: str,
        languages: str = "auto",
        clear_db: bool = False,
        include_body: bool = True,
        include_git: bool = True,
        include_deps: bool = True,
        include_deep: bool = True,
        include_clang: bool = False,
        include_cve: bool = False,
        include_scip: bool = True,
        include_clustering: bool = False,
        include_process: bool = False,
    ) -> dict[str, Any]:
        """Extract code graph from a repository.

        Args:
            repo: Git URL (https/ssh) or local directory path.
            languages: Comma-separated languages or 'auto' for detection.
            clear_db: Clear existing graph data before import.
            include_body: Store source code bodies in graph nodes.
            include_git: Include git history extraction.
            include_deps: Include dependency extraction.
            include_deep: Enable CFG, data flow, and taint analysis.
            include_clang: Enable libclang deep analysis for C/C++.
            include_cve: Enable CVE vulnerability scanning via OSV API.
            include_scip: Enable SCIP compiler-backed call resolution.
            include_clustering: Enable community detection on function graph.
            include_process: Enable execution flow tracing from entry points.

        Returns:
            Dict with extraction results: nodes, edges, resolved_calls, time, etc.
        """
        from archgraph.cli import _detect_languages, _is_git_url

        cloned_dir: Path | None = None
        try:
            if _is_git_url(repo):
                tmp = Path(tempfile.mkdtemp(prefix="archgraph_api_"))
                cloned_dir = tmp / "repo"
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", repo, str(cloned_dir)],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
                )
                if result.returncode != 0:
                    raise RuntimeError(f"git clone failed: {result.stderr[:300]}")
                resolved_path = cloned_dir
            else:
                resolved_path = Path(repo).resolve()
                if not resolved_path.is_dir():
                    raise FileNotFoundError(f"Not a directory: {repo}")

            if languages == "auto":
                langs = _detect_languages(resolved_path)
            else:
                langs = [l.strip() for l in languages.split(",")]

            config = ExtractConfig(
                repo_path=resolved_path,
                languages=langs,
                neo4j_uri=self._uri,
                neo4j_user=self._user,
                neo4j_password=self._password,
                neo4j_database=self._database,
                include_body=include_body,
                include_git=include_git,
                include_deps=include_deps,
                include_deep=include_deep,
                include_clang=include_clang,
                include_cve=include_cve,
                include_scip=include_scip,
                include_clustering=include_clustering,
                include_process=include_process,
            )

            start = time.time()
            builder = GraphBuilder(config)
            graph = builder.build()
            build_time = time.time() - start

            store = self._get_store()
            if clear_db:
                store.clear_repo(resolved_path.name)
            store.create_indexes()
            import_start = time.time()
            import_result = store.import_graph(graph, repo_name=resolved_path.name)
            import_time = time.time() - import_start

            try:
                from archgraph.registry import get_registry
                get_registry().register(
                    resolved_path,
                    neo4j_uri=self._uri,
                    neo4j_database=self._database,
                    languages=langs,
                    stats={"node_count": graph.node_count, "edge_count": graph.edge_count},
                )
            except Exception:
                pass

            stats = graph.stats()
            result: dict[str, Any] = {
                "status": "success",
                "repo": str(resolved_path),
                "languages": langs,
                "nodes": graph.node_count,
                "edges": graph.edge_count,
                "node_types": stats["nodes"],
                "edge_types": stats["edges"],
                "extraction_time": f"{build_time:.1f}s",
                "import_time": f"{import_time:.1f}s",
                "nodes_imported": import_result["nodes_imported"],
                "edges_imported": import_result["edges_imported"],
            }
            if graph.warnings:
                result["warnings"] = graph.warnings
            return result
        finally:
            if cloned_dir and cloned_dir.parent.exists():
                shutil.rmtree(cloned_dir.parent, ignore_errors=True)

    # ── Query ─────────────────────────────────────────────────────────────

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a Cypher query against the graph database."""
        return self._get_store().query(cypher, params or {})

    # ── Search ────────────────────────────────────────────────────────────

    def search(
        self,
        name: str = "",
        type: str = "",
        file_pattern: str = "",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search for symbols by name, type, or file pattern.

        Args:
            name: Symbol name (supports * wildcards).
            type: Filter by type (function, class, struct, interface, enum, module, file).
            file_pattern: Filter by file path pattern (supports * wildcards).
            limit: Max results.
        """
        type_map = {
            "function": "Function", "class": "Class", "struct": "Struct",
            "interface": "Interface", "enum": "Enum", "module": "Module", "file": "File",
        }

        conditions = ["n._id IS NOT NULL"]
        params: dict[str, Any] = {}

        label = type_map.get(type.lower(), type) if type else "_Node"
        cypher_label = f":{label}"

        if name:
            if "*" in name:
                regex = name.replace("*", ".*")
                conditions.append("n.name =~ $name_regex")
                params["name_regex"] = f"(?i){regex}"
            else:
                conditions.append("toLower(n.name) CONTAINS toLower($name)")
                params["name"] = name

        if file_pattern:
            if "*" in file_pattern:
                regex = file_pattern.replace("*", ".*")
                conditions.append("n.file =~ $file_regex")
                params["file_regex"] = f"(?i){regex}"
            else:
                conditions.append("toLower(n.file) CONTAINS toLower($file_pat)")
                params["file_pat"] = file_pattern

        where = " AND ".join(conditions)
        cypher = (
            f"MATCH (n{cypher_label}) WHERE {where} "
            f"RETURN n._id AS id, n.name AS name, labels(n) AS labels, "
            f"n.file AS file, n.line_start AS line "
            f"ORDER BY n.file, n.name LIMIT $limit"
        )
        params["limit"] = limit
        return self._get_store().query(cypher, params)

    # ── Search Calls ──────────────────────────────────────────────────────

    def search_calls(
        self,
        caller: str = "",
        target: str = "",
        file: str = "",
        resolved_only: bool = False,
        source: str = "any",
        max_depth: int = 1,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Search call relationships between functions.

        Args:
            caller: Caller function name (partial match).
            target: Target function name (partial match).
            file: Filter by file path (partial match).
            resolved_only: Only show resolved calls.
            source: Filter by resolution source: "scip", "heuristic", or "any".
            max_depth: Call chain depth (1=direct, >1=transitive).
            limit: Max results.
        """
        conditions = []
        params: dict[str, Any] = {"limit": limit}

        # Build source filter clause
        source_clause = ""
        if source == "scip":
            source_clause = "r.source = 'scip'"
        elif source == "heuristic":
            source_clause = "r.source = 'heuristic'"

        if max_depth > 1:
            params["depth"] = max_depth
            path_filters: list[str] = []
            if resolved_only:
                path_filters.append("r.resolved = true")
            if source_clause:
                path_filters.append(source_clause)
            if path_filters:
                combined = " AND ".join(path_filters)
                path_filter = f"ALL(r IN relationships(path) WHERE {combined})"
            else:
                path_filter = "true"

            if caller:
                conditions.append("toLower(src.name) CONTAINS toLower($caller)")
                params["caller"] = caller
            if target:
                conditions.append("toLower(dst.name) CONTAINS toLower($target)")
                params["target"] = target
            where = " AND ".join(conditions) if conditions else "true"
            cypher = (
                f"MATCH path = (src:Function)-[:CALLS*1..$depth]->(dst:Function) "
                f"WHERE {where} AND {path_filter} "
                f"RETURN src.name AS caller, src.file AS caller_file, "
                f"dst.name AS target, dst.file AS target_file, "
                f"length(path) AS depth ORDER BY depth LIMIT $limit"
            )
        else:
            if caller:
                conditions.append("toLower(f.name) CONTAINS toLower($caller)")
                params["caller"] = caller
            if target:
                conditions.append("toLower(t.name) CONTAINS toLower($target)")
                params["target"] = target
            if file:
                conditions.append(
                    "(toLower(f.file) CONTAINS toLower($file) "
                    "OR toLower(t.file) CONTAINS toLower($file))"
                )
                params["file"] = file
            if resolved_only:
                conditions.append("c.resolved = true")
            if source == "scip":
                conditions.append("c.source = 'scip'")
            elif source == "heuristic":
                conditions.append("c.source = 'heuristic'")
            where = " WHERE " + " AND ".join(conditions) if conditions else ""
            cypher = (
                f"MATCH (f:Function)-[c:CALLS]->(t:Function){where} "
                f"RETURN f.name AS caller, f.file AS caller_file, "
                f"t.name AS target, t.file AS target_file, "
                f"c.resolved AS resolved, c.source AS source "
                f"ORDER BY f.file, f.name LIMIT $limit"
            )
        return self._get_store().query(cypher, params)

    # ── Source ────────────────────────────────────────────────────────────

    def source(self, symbol_id: str) -> dict[str, Any] | None:
        """Get source code of a symbol."""
        return self._get_store().get_source(symbol_id)

    # ── Repos ─────────────────────────────────────────────────────────────

    def repos(self) -> list[dict[str, Any]]:
        """List all extracted repositories."""
        try:
            from archgraph.registry import get_registry
            return [e.to_dict() for e in get_registry().list_repos()]
        except Exception:
            return []

    # ── Impact ────────────────────────────────────────────────────────────

    def impact(
        self, symbol_id: str, direction: str = "downstream", max_depth: int = 5,
    ) -> dict[str, Any]:
        """Analyze blast radius of a function."""
        from archgraph.tool.impact import ImpactAnalyzer
        analyzer = ImpactAnalyzer(self._get_store())
        return analyzer.analyze_impact(symbol_id, direction, max_depth)

    # ── Context ───────────────────────────────────────────────────────────

    def context(self, symbol_id: str) -> dict[str, Any]:
        """Get 360-degree view of a symbol — properties, callers, callees, cluster, security labels."""
        store = self._get_store()
        symbol = store.query(
            "MATCH (n:_Node {_id: $id}) RETURN properties(n) AS props",
            {"id": symbol_id},
        )
        if not symbol:
            return {"error": f"Symbol not found: {symbol_id}"}

        props = symbol[0].get("props", {})
        props.pop("body", None)

        callers = store.query(
            "MATCH (f:Function)-[c:CALLS]->(n:_Node {_id: $id}) "
            "RETURN f._id AS id, f.name AS name, f.file AS file, "
            "c.resolved AS resolved, c.source AS source",
            {"id": symbol_id},
        )
        callees = store.query(
            "MATCH (n:_Node {_id: $id})-[c:CALLS]->(f:Function) "
            "RETURN f._id AS id, f.name AS name, f.file AS file, "
            "c.resolved AS resolved, c.source AS source",
            {"id": symbol_id},
        )
        cluster = store.query(
            "MATCH (n:_Node {_id: $id})-[:BELONGS_TO]->(c:Cluster) "
            "RETURN c._id AS id, c.name AS name, c.cohesion AS cohesion",
            {"id": symbol_id},
        )
        security = {
            k: True for k in [
                "is_input_source", "is_dangerous_sink", "is_allocator",
                "is_crypto", "is_parser", "touches_unsafe",
            ] if props.get(k)
        }
        return {
            "symbol": {"id": symbol_id, "properties": props},
            "callers": callers,
            "callees": callees,
            "cluster": cluster[0] if cluster else None,
            "security_labels": security,
        }

    # ── Stats ─────────────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Get graph statistics — node/edge counts, clusters, processes."""
        store = self._get_store()
        db_stats = store.stats()
        cluster_count = store.query("MATCH (c:Cluster) RETURN count(c) AS count")
        process_count = store.query("MATCH (p:Process) RETURN count(p) AS count")
        return {
            "graph_stats": db_stats,
            "clusters": cluster_count[0]["count"] if cluster_count else 0,
            "processes": process_count[0]["count"] if process_count else 0,
        }

    # ── Detect Changes ────────────────────────────────────────────────────

    def detect_changes(self, changed_files: list[str]) -> dict[str, Any]:
        """Analyze impact of changed files on the codebase."""
        from archgraph.tool.impact import ImpactAnalyzer
        analyzer = ImpactAnalyzer(self._get_store())
        return analyzer.analyze_change_impact(changed_files)

    # ── Find Vulnerabilities ──────────────────────────────────────────────

    def find_vulnerabilities(self, severity: str | None = None) -> list[dict[str, Any]]:
        """Find known CVE vulnerabilities affecting project dependencies."""
        results = self._get_store().query(
            "MATCH (d:Dependency)-[:AFFECTED_BY]->(v:Vulnerability) "
            "RETURN d.name AS dependency, d.version AS version, "
            "v.vuln_id AS vuln_id, v.summary AS summary, v.severity AS severity"
        )
        if severity:
            results = [r for r in results if severity.upper() in (r.get("severity") or "").upper()]
        return results
