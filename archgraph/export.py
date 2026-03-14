"""Graph export — GraphML, JSON, CSV formats."""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any

from archgraph.graph.schema import GraphData

logger = logging.getLogger(__name__)


def export_json(graph: GraphData, output_path: Path) -> Path:
    """Export graph as JSON."""
    data = {
        "nodes": [
            {"id": n.id, "label": n.label, **n.properties}
            for n in graph.nodes
        ],
        "edges": [
            {"source": e.source_id, "target": e.target_id, "type": e.type, **e.properties}
            for e in graph.edges
        ],
        "stats": graph.stats(),
    }
    output_path.write_text(json.dumps(data, indent=2))
    logger.info("Exported %d nodes, %d edges to %s", graph.node_count, graph.edge_count, output_path)
    return output_path


def export_graphml(graph: GraphData, output_path: Path) -> Path:
    """Export graph as GraphML (compatible with Gephi, yEd, etc.)."""
    try:
        import networkx as nx
    except ImportError:
        raise ImportError("networkx required: pip install networkx")

    g = nx.DiGraph()

    for node in graph.nodes:
        attrs = {"label": node.label}
        for k, v in node.properties.items():
            attrs[k] = str(v) if v is not None else ""
        g.add_node(node.id, **attrs)

    for edge in graph.edges:
        attrs = {"type": edge.type}
        for k, v in edge.properties.items():
            attrs[k] = str(v) if v is not None else ""
        g.add_edge(edge.source_id, edge.target_id, **attrs)

    nx.write_graphml(g, str(output_path))
    logger.info("Exported GraphML to %s", output_path)
    return output_path


def export_csv(graph: GraphData, output_dir: Path) -> dict[str, Path]:
    """Export graph as CSV files (nodes.csv, edges.csv)."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Nodes CSV
    nodes_path = output_dir / "nodes.csv"
    all_keys: set[str] = set()
    for n in graph.nodes:
        all_keys.update(n.properties.keys())

    fieldnames = ["id", "label"] + sorted(all_keys)
    with open(nodes_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for n in graph.nodes:
            row = {"id": n.id, "label": n.label}
            row.update({k: str(v) if v is not None else "" for k, v in n.properties.items()})
            writer.writerow(row)

    # Edges CSV
    edges_path = output_dir / "edges.csv"
    all_edge_keys: set[str] = set()
    for e in graph.edges:
        all_edge_keys.update(e.properties.keys())

    edge_fieldnames = ["source", "target", "type"] + sorted(all_edge_keys)
    with open(edges_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=edge_fieldnames)
        writer.writeheader()
        for e in graph.edges:
            row = {"source": e.source_id, "target": e.target_id, "type": e.type}
            row.update({k: str(v) if v is not None else "" for k, v in e.properties.items()})
            writer.writerow(row)

    logger.info("Exported CSV to %s", output_dir)
    return {"nodes": nodes_path, "edges": edges_path}
