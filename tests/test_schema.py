"""Tests for graph schema data structures."""

from archgraph.graph.schema import Node, Edge, GraphData, NodeLabel, EdgeType


def test_node_creation():
    node = Node(id="func:main", label=NodeLabel.FUNCTION, properties={"name": "main"})
    assert node.id == "func:main"
    assert node.label == "Function"
    assert node.properties["name"] == "main"


def test_node_equality():
    a = Node(id="func:main", label=NodeLabel.FUNCTION)
    b = Node(id="func:main", label=NodeLabel.FUNCTION)
    assert a == b
    assert hash(a) == hash(b)


def test_edge_creation():
    edge = Edge(source_id="file:a.c", target_id="func:main", type=EdgeType.CONTAINS)
    assert edge.source_id == "file:a.c"
    assert edge.target_id == "func:main"
    assert edge.type == "CONTAINS"


def test_graph_data_add():
    g = GraphData()
    g.add_node("f1", NodeLabel.FILE, path="a.c")
    g.add_node("fn1", NodeLabel.FUNCTION, name="main")
    g.add_edge("f1", "fn1", EdgeType.CONTAINS)

    assert g.node_count == 2
    assert g.edge_count == 1


def test_graph_data_merge():
    g1 = GraphData()
    g1.add_node("f1", NodeLabel.FILE, path="a.c")

    g2 = GraphData()
    g2.add_node("f2", NodeLabel.FILE, path="b.c")
    g2.add_edge("f1", "f2", EdgeType.IMPORTS)

    g1.merge(g2)
    assert g1.node_count == 2
    assert g1.edge_count == 1


def test_graph_data_deduplicate():
    g = GraphData()
    g.add_node("f1", NodeLabel.FILE, path="a.c")
    g.add_node("f1", NodeLabel.FILE, path="a.c", size=100)  # duplicate
    g.add_edge("f1", "f2", EdgeType.IMPORTS)
    g.add_edge("f1", "f2", EdgeType.IMPORTS)  # duplicate

    g.deduplicate()
    assert g.node_count == 1
    assert g.edge_count == 1
    # Later properties should overwrite
    assert g.nodes[0].properties.get("size") == 100


def test_graph_data_stats():
    g = GraphData()
    g.add_node("f1", NodeLabel.FILE, path="a.c")
    g.add_node("fn1", NodeLabel.FUNCTION, name="main")
    g.add_node("fn2", NodeLabel.FUNCTION, name="helper")
    g.add_edge("f1", "fn1", EdgeType.CONTAINS)
    g.add_edge("f1", "fn2", EdgeType.CONTAINS)
    g.add_edge("fn1", "fn2", EdgeType.CALLS)

    stats = g.stats()
    assert stats["nodes"][NodeLabel.FILE] == 1
    assert stats["nodes"][NodeLabel.FUNCTION] == 2
    assert stats["edges"][EdgeType.CONTAINS] == 2
    assert stats["edges"][EdgeType.CALLS] == 1
