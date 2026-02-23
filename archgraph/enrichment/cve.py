"""CVE enrichment — queries OSV API for known vulnerabilities in dependencies."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any

from archgraph.config import OSV_API_URL, OSV_QUERY_TIMEOUT, SOURCE_TO_OSV_ECOSYSTEM
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

logger = logging.getLogger(__name__)

_VERSION_PREFIX_RE = re.compile(r"^[~^>=<vV!*]+\s*")


def _clean_version(version: str) -> str:
    """Strip common version prefixes (^, ~, >=, v, etc.)."""
    return _VERSION_PREFIX_RE.sub("", version).strip()


class CveEnricher:
    """Enriches graph with vulnerability data from OSV (osv.dev)."""

    def __init__(self, batch_size: int = 1000) -> None:
        self._batch_size = batch_size

    def enrich(self, graph: GraphData) -> int:
        """Query OSV for vulnerabilities affecting dependencies.

        Returns the number of Vulnerability nodes added.
        """
        dep_nodes = [n for n in graph.nodes if n.label == NodeLabel.DEPENDENCY]
        if not dep_nodes:
            return 0

        # Build queries for OSV batch API
        queries: list[dict[str, Any]] = []
        dep_index: list[Any] = []  # parallel list to map results back

        for node in dep_nodes:
            name = node.properties.get("name", "")
            version = _clean_version(node.properties.get("version", ""))
            source = node.properties.get("source", "")

            if not name or not version:
                continue

            ecosystem = SOURCE_TO_OSV_ECOSYSTEM.get(source, "")
            if not ecosystem:
                continue

            queries.append({
                "version": version,
                "package": {"name": name, "ecosystem": ecosystem},
            })
            dep_index.append(node)

        if not queries:
            return 0

        vuln_count = 0
        # Process in batches
        for batch_start in range(0, len(queries), self._batch_size):
            batch_queries = queries[batch_start : batch_start + self._batch_size]
            batch_deps = dep_index[batch_start : batch_start + self._batch_size]

            try:
                results = self._query_osv(batch_queries)
            except Exception:
                logger.warning("OSV API query failed — skipping CVE enrichment", exc_info=True)
                return vuln_count

            for dep_node, result in zip(batch_deps, results):
                vulns = result.get("vulns", [])
                for vuln in vulns:
                    vuln_id = vuln.get("id", "")
                    if not vuln_id:
                        continue

                    # Create Vulnerability node
                    node_id = f"vuln:{vuln_id}"
                    severity = self._extract_severity(vuln)
                    summary = vuln.get("summary", "")[:500]

                    graph.add_node(
                        node_id,
                        NodeLabel.VULNERABILITY,
                        vuln_id=vuln_id,
                        summary=summary,
                        severity=severity,
                        aliases=",".join(vuln.get("aliases", [])),
                    )

                    # AFFECTED_BY edge: Dependency → Vulnerability
                    graph.add_edge(dep_node.id, node_id, EdgeType.AFFECTED_BY)
                    vuln_count += 1

        logger.info("CVE enrichment: %d vulnerabilities found", vuln_count)
        return vuln_count

    def _query_osv(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Send a batch query to OSV API. Returns list of result dicts."""
        payload = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            OSV_API_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=OSV_QUERY_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        return data.get("results", [{}] * len(queries))

    def _extract_severity(self, vuln: dict[str, Any]) -> str:
        """Extract severity string from OSV vulnerability data."""
        severity_list = vuln.get("severity", [])
        if severity_list:
            return severity_list[0].get("score", "")
        # Fallback: check database_specific
        db_specific = vuln.get("database_specific", {})
        return db_specific.get("severity", "")
