"""Graph schema, builder, and Neo4j storage."""

from archgraph.graph.schema import Node, Edge, GraphData


def __getattr__(name: str):
    """Lazy import to avoid circular dependency with extractors."""
    if name == "GraphBuilder":
        from archgraph.graph.builder import GraphBuilder
        return GraphBuilder
    if name == "Neo4jStore":
        from archgraph.graph.neo4j_store import Neo4jStore
        return Neo4jStore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["Node", "Edge", "GraphData", "GraphBuilder", "Neo4jStore"]
