"""Clustering enrichment — community detection using Leiden algorithm via networkx."""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

logger = logging.getLogger(__name__)


class ClusterEnricher:
    """Enriches graph with functional clusters using community detection."""

    def __init__(self, resolution: float = 1.0) -> None:
        self._resolution = resolution

    def enrich(self, graph: GraphData) -> int:
        """Detect communities and add Cluster nodes + BELONGS_TO edges.

        Returns number of clusters found.
        """
        # Build networkx graph from function nodes and CALLS edges
        nx_graph = nx.Graph()
        func_ids: set[str] = set()

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION:
                func_ids.add(node.id)
                nx_graph.add_node(node.id)

        for edge in graph.edges:
            if edge.type == EdgeType.CALLS:
                if edge.source_id in func_ids and edge.target_id in func_ids:
                    nx_graph.add_edge(edge.source_id, edge.target_id)

        if nx_graph.number_of_nodes() < 3:
            logger.info("Too few functions for clustering, skipping")
            return 0

        # Community detection using greedy modularity (Louvain approximation)
        try:
            from networkx.algorithms.community import greedy_modularity_communities

            communities = list(
                greedy_modularity_communities(
                    nx_graph, weight=None, resolution=self._resolution
                )
            )
        except Exception:
            logger.warning("Community detection failed, skipping clustering")
            return 0

        if not communities:
            return 0

        # Assign cluster names based on most common file in each community
        cluster_count = 0
        for idx, community in enumerate(communities):
            if len(community) < 2:
                continue  # Skip singleton clusters

            cluster_id = f"cluster:{idx}"
            cluster_name = self._name_cluster(community, graph)

            # Calculate cohesion score
            subgraph = nx_graph.subgraph(community)
            cohesion = self._calculate_cohesion(subgraph)

            graph.add_node(
                cluster_id,
                NodeLabel.CLUSTER,
                name=cluster_name,
                size=len(community),
                cohesion=cohesion,
            )

            # BELONGS_TO edge: Function → Cluster
            for func_id in community:
                graph.add_edge(func_id, cluster_id, EdgeType.BELONGS_TO)

            cluster_count += 1

        logger.info("Detected %d clusters from %d functions", cluster_count, len(func_ids))
        return cluster_count

    def _name_cluster(self, community: set[str], graph: GraphData) -> str:
        """Name a cluster based on the most common source file."""
        from collections import Counter

        file_counter: Counter[str] = Counter()
        for node in graph.nodes:
            if node.id in community:
                file_path = node.properties.get("file", "")
                if file_path:
                    # Use directory as grouping
                    parts = file_path.split("/")
                    if len(parts) > 1:
                        file_counter[parts[-2]] += 1
                    else:
                        file_counter[parts[0]] += 1

        if file_counter:
            top_file = file_counter.most_common(1)[0][0]
            return f"{top_file}_cluster"
        return f"cluster_{len(community)}_funcs"

    def _calculate_cohesion(self, subgraph: nx.Graph) -> float:
        """Calculate cohesion score (density) of a subgraph."""
        if subgraph.number_of_nodes() < 2:
            return 0.0
        return round(nx.density(subgraph), 3)
