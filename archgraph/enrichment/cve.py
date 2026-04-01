"""CVE enrichment — queries OSV API for known vulnerabilities in dependencies."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from archgraph.config import OSV_API_URL, OSV_QUERY_TIMEOUT, SOURCE_TO_OSV_ECOSYSTEM
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

logger = logging.getLogger(__name__)

_VERSION_PREFIX_RE = re.compile(r"^[~^>=<vV!*]+\s*")
_VULN_API_URL = "https://api.osv.dev/v1/vulns/"


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

        # Phase 1: Batch query to find which vulns affect our deps
        vuln_dep_map: dict[str, list[Any]] = {}  # vuln_id -> [dep_nodes]
        for batch_start in range(0, len(queries), self._batch_size):
            batch_queries = queries[batch_start : batch_start + self._batch_size]
            batch_deps = dep_index[batch_start : batch_start + self._batch_size]

            try:
                results = self._query_osv_batch(batch_queries)
            except Exception:
                logger.warning("OSV batch query failed — skipping CVE enrichment", exc_info=True)
                return 0

            for dep_node, result in zip(batch_deps, results):
                for vuln in result.get("vulns", []):
                    vuln_id = vuln.get("id", "")
                    if vuln_id:
                        vuln_dep_map.setdefault(vuln_id, []).append(dep_node)

        if not vuln_dep_map:
            logger.info("CVE enrichment: no vulnerabilities found")
            return 0

        # Phase 2: Fetch full details for each unique vulnerability
        vuln_details = self._fetch_vuln_details(list(vuln_dep_map.keys()))

        # Phase 3: Create nodes and edges
        vuln_count = 0
        for vuln_id, dep_nodes_list in vuln_dep_map.items():
            detail = vuln_details.get(vuln_id, {})
            severity = self._extract_severity(detail)
            summary = detail.get("summary", "")[:500]
            aliases = detail.get("aliases", [])
            db_severity = detail.get("database_specific", {}).get("severity", "")

            node_id = f"vuln:{vuln_id}"
            graph.add_node(
                node_id,
                NodeLabel.VULNERABILITY,
                vuln_id=vuln_id,
                summary=summary,
                severity=severity,
                severity_label=db_severity,
                aliases=",".join(aliases),
            )

            for dep_node in dep_nodes_list:
                graph.add_edge(dep_node.id, node_id, EdgeType.AFFECTED_BY)
                vuln_count += 1

        logger.info("CVE enrichment: %d vulnerabilities found across %d edges", len(vuln_dep_map), vuln_count)
        return vuln_count

    def _query_osv_batch(self, queries: list[dict[str, Any]]) -> list[dict[str, Any]]:
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

    def _fetch_vuln_details(self, vuln_ids: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch full details for each vulnerability ID in parallel."""
        details: dict[str, dict[str, Any]] = {}

        def _fetch_one(vuln_id: str) -> tuple[str, dict[str, Any]]:
            try:
                req = urllib.request.Request(
                    f"{_VULN_API_URL}{vuln_id}",
                    headers={"Accept": "application/json"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=OSV_QUERY_TIMEOUT) as resp:
                    return vuln_id, json.loads(resp.read().decode("utf-8"))
            except Exception:
                logger.debug("Failed to fetch details for %s", vuln_id)
                return vuln_id, {}

        workers = min(len(vuln_ids), 10)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_fetch_one, vid) for vid in vuln_ids]
            for f in as_completed(futures):
                vid, data = f.result()
                details[vid] = data

        logger.debug("Fetched details for %d/%d vulnerabilities", len(details), len(vuln_ids))
        return details

    def _extract_severity(self, vuln: dict[str, Any]) -> str:
        """Extract severity string from OSV vulnerability data."""
        severity_list = vuln.get("severity", [])
        if severity_list:
            return severity_list[0].get("score", "")
        # Fallback: check database_specific
        db_specific = vuln.get("database_specific", {})
        return db_specific.get("severity", "")
