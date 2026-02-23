"""Neo4j storage backend — connection, bulk import, indexes, and querying."""

from __future__ import annotations

import logging
from typing import Any

from neo4j import GraphDatabase, Driver, Session

from archgraph.config import NEO4J_BATCH_SIZE
from archgraph.graph.schema import GraphData, Node, Edge, NodeLabel

logger = logging.getLogger(__name__)


# Indexes to create for query performance
_INDEXES: list[tuple[str, list[str]]] = [
    (NodeLabel.FILE, ["path"]),
    (NodeLabel.FUNCTION, ["name", "file"]),
    (NodeLabel.FUNCTION, ["is_input_source"]),
    (NodeLabel.FUNCTION, ["is_dangerous_sink"]),
    (NodeLabel.FUNCTION, ["is_allocator"]),
    (NodeLabel.FUNCTION, ["is_crypto"]),
    (NodeLabel.FUNCTION, ["is_parser"]),
    (NodeLabel.CLASS, ["name"]),
    (NodeLabel.STRUCT, ["name"]),
    (NodeLabel.MODULE, ["name"]),
    (NodeLabel.COMMIT, ["hash"]),
    (NodeLabel.AUTHOR, ["email"]),
    (NodeLabel.DEPENDENCY, ["name"]),
    (NodeLabel.TAG, ["name"]),
    (NodeLabel.BASIC_BLOCK, ["function", "file"]),
    (NodeLabel.VULNERABILITY, ["vuln_id"]),
]


class Neo4jStore:
    """Manages Neo4j connection and graph operations."""

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "neo4j",
        database: str = "neo4j",
    ) -> None:
        self._uri = uri
        self._user = user
        self._password = password
        self._database = database
        self._driver: Driver | None = None

    def connect(self) -> None:
        """Establish connection to Neo4j."""
        self._driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
        self._driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", self._uri)

    def close(self) -> None:
        """Close the Neo4j connection."""
        if self._driver:
            self._driver.close()
            self._driver = None

    def __enter__(self) -> Neo4jStore:
        self.connect()
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    @property
    def driver(self) -> Driver:
        if self._driver is None:
            raise RuntimeError("Not connected. Call connect() first.")
        return self._driver

    def _session(self) -> Session:
        return self.driver.session(database=self._database)

    def create_indexes(self) -> None:
        """Create indexes for common query patterns."""
        with self._session() as session:
            # Unique constraint on node id
            session.run(
                "CREATE CONSTRAINT node_id IF NOT EXISTS "
                "FOR (n:_Node) REQUIRE n._id IS UNIQUE"
            )
            for label, props in _INDEXES:
                for prop in props:
                    index_name = f"idx_{label.lower()}_{prop}"
                    session.run(
                        f"CREATE INDEX {index_name} IF NOT EXISTS "
                        f"FOR (n:{label}) ON (n.{prop})"
                    )
            logger.info("Created %d indexes", len(_INDEXES))

    def clear(self) -> None:
        """Delete all nodes and relationships. Use with caution."""
        with self._session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            logger.info("Cleared all graph data")

    def import_graph(self, graph: GraphData) -> dict[str, int]:
        """Bulk import nodes and edges into Neo4j. Returns counts."""
        node_count = self._import_nodes(graph.nodes)
        edge_count = self._import_edges(graph.edges)
        return {"nodes_imported": node_count, "edges_imported": edge_count}

    def _import_nodes(self, nodes: list[Node]) -> int:
        """Batch-import nodes."""
        if not nodes:
            return 0

        # Group nodes by label for efficient batch creation
        by_label: dict[str, list[Node]] = {}
        for node in nodes:
            by_label.setdefault(node.label, []).append(node)

        total = 0
        with self._session() as session:
            for label, label_nodes in by_label.items():
                for batch_start in range(0, len(label_nodes), NEO4J_BATCH_SIZE):
                    batch = label_nodes[batch_start : batch_start + NEO4J_BATCH_SIZE]
                    records = []
                    for node in batch:
                        props = dict(node.properties)
                        props["_id"] = node.id
                        records.append(props)

                    session.run(
                        f"UNWIND $records AS props "
                        f"MERGE (n:{label} {{_id: props._id}}) "
                        f"SET n += props "
                        f"SET n:_Node",
                        records=records,
                    )
                    total += len(batch)

                logger.debug("Imported %d %s nodes", len(label_nodes), label)

        logger.info("Imported %d nodes total", total)
        return total

    def _import_edges(self, edges: list[Edge]) -> int:
        """Batch-import edges."""
        if not edges:
            return 0

        # Group edges by type
        by_type: dict[str, list[Edge]] = {}
        for edge in edges:
            by_type.setdefault(edge.type, []).append(edge)

        total = 0
        with self._session() as session:
            for rel_type, type_edges in by_type.items():
                for batch_start in range(0, len(type_edges), NEO4J_BATCH_SIZE):
                    batch = type_edges[batch_start : batch_start + NEO4J_BATCH_SIZE]
                    records = []
                    for edge in batch:
                        rec = dict(edge.properties)
                        rec["_src"] = edge.source_id
                        rec["_tgt"] = edge.target_id
                        records.append(rec)

                    session.run(
                        f"UNWIND $records AS rec "
                        f"MATCH (a:_Node {{_id: rec._src}}) "
                        f"MATCH (b:_Node {{_id: rec._tgt}}) "
                        f"MERGE (a)-[r:{rel_type}]->(b) "
                        f"SET r += rec",
                        records=records,
                    )
                    total += len(batch)

                logger.debug("Imported %d %s edges", len(type_edges), rel_type)

        logger.info("Imported %d edges total", total)
        return total

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a Cypher query and return results as list of dicts."""
        with self._session() as session:
            result = session.run(cypher, parameters=params or {})
            return [record.data() for record in result]

    def schema_info(self) -> dict[str, Any]:
        """Return the graph schema — node labels, relationship types, and property keys."""
        with self._session() as session:
            labels_result = session.run("CALL db.labels()")
            labels = [r["label"] for r in labels_result]

            rel_result = session.run("CALL db.relationshipTypes()")
            rel_types = [r["relationshipType"] for r in rel_result]

            prop_result = session.run("CALL db.propertyKeys()")
            prop_keys = [r["propertyKey"] for r in prop_result]

        return {
            "node_labels": labels,
            "relationship_types": rel_types,
            "property_keys": prop_keys,
        }

    def stats(self) -> dict[str, Any]:
        """Return node and edge counts per type."""
        with self._session() as session:
            node_result = session.run(
                "MATCH (n) "
                "WITH labels(n) AS lbls, count(*) AS cnt "
                "UNWIND lbls AS lbl "
                "RETURN lbl, sum(cnt) AS count "
                "ORDER BY count DESC"
            )
            node_counts = {r["lbl"]: r["count"] for r in node_result}

            edge_result = session.run(
                "MATCH ()-[r]->() "
                "RETURN type(r) AS type, count(*) AS count "
                "ORDER BY count DESC"
            )
            edge_counts = {r["type"]: r["count"] for r in edge_result}

        return {"nodes": node_counts, "edges": edge_counts}
