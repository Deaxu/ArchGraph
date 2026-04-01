"""Tests for CVE enrichment (OSV API)."""

import json
from unittest.mock import patch, MagicMock

import pytest

from archgraph.enrichment.cve import CveEnricher, _clean_version
from archgraph.graph.schema import GraphData, NodeLabel, EdgeType


def _make_dep_graph(deps: list[dict]) -> GraphData:
    """Helper: create a GraphData with Dependency nodes."""
    graph = GraphData()
    for dep in deps:
        graph.add_node(
            f"dep:{dep['name']}",
            NodeLabel.DEPENDENCY,
            name=dep["name"],
            version=dep.get("version", ""),
            source=dep.get("source", ""),
        )
    return graph


def _mock_vuln_detail(vuln_id: str, summary: str = "", severity_score: str = "",
                       aliases: list[str] | None = None, db_severity: str = "") -> dict:
    """Build a mock OSV vuln detail response."""
    detail: dict = {"id": vuln_id}
    if summary:
        detail["summary"] = summary
    if severity_score:
        detail["severity"] = [{"type": "CVSS_V3", "score": severity_score}]
    if aliases:
        detail["aliases"] = aliases
    if db_severity:
        detail["database_specific"] = {"severity": db_severity}
    return detail


def test_no_deps():
    """CveEnricher returns 0 when there are no dependency nodes."""
    graph = GraphData()
    enricher = CveEnricher()
    assert enricher.enrich(graph) == 0


def test_deps_without_version():
    """Dependencies without a version string are skipped."""
    graph = _make_dep_graph([
        {"name": "lodash", "version": "", "source": "package.json"},
    ])
    enricher = CveEnricher()
    with patch.object(enricher, "_query_osv_batch") as mock_query:
        result = enricher.enrich(graph)
    assert result == 0
    mock_query.assert_not_called()


def test_unsupported_ecosystem():
    """Dependencies from unsupported ecosystems are skipped."""
    graph = _make_dep_graph([
        {"name": "some-lib", "version": "1.0.0", "source": "vcpkg.json"},
    ])
    enricher = CveEnricher()
    with patch.object(enricher, "_query_osv_batch") as mock_query:
        result = enricher.enrich(graph)
    assert result == 0
    mock_query.assert_not_called()


def test_successful_enrichment():
    """Mock OSV response creates Vulnerability nodes and AFFECTED_BY edges with full details."""
    graph = _make_dep_graph([
        {"name": "serde", "version": "1.0.100", "source": "Cargo.toml"},
    ])

    mock_batch_response = [
        {
            "vulns": [
                {"id": "GHSA-xxxx-yyyy-zzzz"},
            ],
        },
    ]

    mock_detail = _mock_vuln_detail(
        "GHSA-xxxx-yyyy-zzzz",
        summary="Deserialization vulnerability in serde",
        severity_score="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        aliases=["CVE-2024-1234"],
        db_severity="CRITICAL",
    )

    enricher = CveEnricher()
    with patch.object(enricher, "_query_osv_batch", return_value=mock_batch_response), \
         patch.object(enricher, "_fetch_vuln_details", return_value={"GHSA-xxxx-yyyy-zzzz": mock_detail}):
        result = enricher.enrich(graph)

    assert result == 1

    # Check Vulnerability node
    vuln_nodes = [n for n in graph.nodes if n.label == NodeLabel.VULNERABILITY]
    assert len(vuln_nodes) == 1
    assert vuln_nodes[0].id == "vuln:GHSA-xxxx-yyyy-zzzz"
    assert vuln_nodes[0].properties["vuln_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert "Deserialization" in vuln_nodes[0].properties["summary"]
    assert vuln_nodes[0].properties["aliases"] == "CVE-2024-1234"
    assert "CVSS:3.1" in vuln_nodes[0].properties["severity"]
    assert vuln_nodes[0].properties["severity_label"] == "CRITICAL"

    # Check AFFECTED_BY edge
    affected_edges = [e for e in graph.edges if e.type == EdgeType.AFFECTED_BY]
    assert len(affected_edges) == 1
    assert affected_edges[0].source_id == "dep:serde"
    assert affected_edges[0].target_id == "vuln:GHSA-xxxx-yyyy-zzzz"


def test_no_vulns_found():
    """When OSV returns no vulns, no nodes are added."""
    graph = _make_dep_graph([
        {"name": "tokio", "version": "1.35.0", "source": "Cargo.toml"},
    ])

    mock_batch_response = [{"vulns": []}]

    enricher = CveEnricher()
    with patch.object(enricher, "_query_osv_batch", return_value=mock_batch_response):
        result = enricher.enrich(graph)

    assert result == 0
    vuln_nodes = [n for n in graph.nodes if n.label == NodeLabel.VULNERABILITY]
    assert len(vuln_nodes) == 0


def test_network_error_graceful():
    """Network errors are handled gracefully — returns 0, no crash."""
    graph = _make_dep_graph([
        {"name": "express", "version": "4.18.0", "source": "package.json"},
    ])

    enricher = CveEnricher()
    with patch.object(enricher, "_query_osv_batch", side_effect=ConnectionError("timeout")):
        result = enricher.enrich(graph)

    assert result == 0


def test_clean_version():
    """Version prefix stripping works correctly."""
    assert _clean_version("^1.2.3") == "1.2.3"
    assert _clean_version("~1.2.3") == "1.2.3"
    assert _clean_version(">=1.0.0") == "1.0.0"
    assert _clean_version("v2.1.0") == "2.1.0"
    assert _clean_version("1.0.0") == "1.0.0"
    assert _clean_version("") == ""
    assert _clean_version("^>=1.5") == "1.5"


def test_multiple_deps_batch():
    """Multiple dependencies are batched and processed correctly."""
    graph = _make_dep_graph([
        {"name": "serde", "version": "1.0.100", "source": "Cargo.toml"},
        {"name": "tokio", "version": "1.35.0", "source": "Cargo.toml"},
        {"name": "express", "version": "4.18.0", "source": "package.json"},
    ])

    mock_batch_response = [
        {"vulns": [{"id": "GHSA-1111"}]},
        {"vulns": []},
        {"vulns": [{"id": "GHSA-2222"}, {"id": "GHSA-3333"}]},
    ]

    mock_details = {
        "GHSA-1111": _mock_vuln_detail("GHSA-1111", summary="vuln1", db_severity="HIGH"),
        "GHSA-2222": _mock_vuln_detail("GHSA-2222", summary="vuln2", db_severity="MEDIUM"),
        "GHSA-3333": _mock_vuln_detail("GHSA-3333", summary="vuln3",
                                        aliases=["CVE-2024-5678"], db_severity="LOW"),
    }

    enricher = CveEnricher()
    with patch.object(enricher, "_query_osv_batch", return_value=mock_batch_response), \
         patch.object(enricher, "_fetch_vuln_details", return_value=mock_details):
        result = enricher.enrich(graph)

    assert result == 3
    vuln_nodes = [n for n in graph.nodes if n.label == NodeLabel.VULNERABILITY]
    assert len(vuln_nodes) == 3
    vuln_ids = {n.properties["vuln_id"] for n in vuln_nodes}
    assert vuln_ids == {"GHSA-1111", "GHSA-2222", "GHSA-3333"}

    affected_edges = [e for e in graph.edges if e.type == EdgeType.AFFECTED_BY]
    assert len(affected_edges) == 3


def test_shared_vuln_across_deps():
    """A single vulnerability affecting multiple dependencies creates one node, multiple edges."""
    graph = _make_dep_graph([
        {"name": "pkg-a", "version": "1.0.0", "source": "package.json"},
        {"name": "pkg-b", "version": "2.0.0", "source": "package.json"},
    ])

    # Both deps affected by the same vuln
    mock_batch_response = [
        {"vulns": [{"id": "GHSA-shared"}]},
        {"vulns": [{"id": "GHSA-shared"}]},
    ]

    mock_details = {
        "GHSA-shared": _mock_vuln_detail("GHSA-shared", summary="Shared vuln",
                                          severity_score="CVSS:3.1/AV:N", db_severity="HIGH"),
    }

    enricher = CveEnricher()
    with patch.object(enricher, "_query_osv_batch", return_value=mock_batch_response), \
         patch.object(enricher, "_fetch_vuln_details", return_value=mock_details):
        result = enricher.enrich(graph)

    assert result == 2  # 2 edges (one per dep)
    vuln_nodes = [n for n in graph.nodes if n.label == NodeLabel.VULNERABILITY]
    assert len(vuln_nodes) == 1  # but only 1 vuln node

    affected_edges = [e for e in graph.edges if e.type == EdgeType.AFFECTED_BY]
    assert len(affected_edges) == 2
    sources = {e.source_id for e in affected_edges}
    assert sources == {"dep:pkg-a", "dep:pkg-b"}


def test_detail_fetch_failure_graceful():
    """If detail fetch fails for a vuln, node is still created with empty fields."""
    graph = _make_dep_graph([
        {"name": "serde", "version": "1.0.0", "source": "Cargo.toml"},
    ])

    mock_batch_response = [{"vulns": [{"id": "GHSA-fail"}]}]
    # Detail fetch returns empty dict (simulating failure)
    mock_details = {"GHSA-fail": {}}

    enricher = CveEnricher()
    with patch.object(enricher, "_query_osv_batch", return_value=mock_batch_response), \
         patch.object(enricher, "_fetch_vuln_details", return_value=mock_details):
        result = enricher.enrich(graph)

    assert result == 1
    vuln_nodes = [n for n in graph.nodes if n.label == NodeLabel.VULNERABILITY]
    assert len(vuln_nodes) == 1
    assert vuln_nodes[0].properties["summary"] == ""
    assert vuln_nodes[0].properties["severity"] == ""
