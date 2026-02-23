"""Tests for graph schema data structures."""

from archgraph.graph.schema import Node, Edge, GraphData, NodeLabel, EdgeType, GraphDiff, NodeChange


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


# ── Graph Diff Tests ─────────────────────────────────────────────────────────


def test_diff_added_nodes():
    old = GraphData()
    old.add_node("f1", NodeLabel.FILE, path="a.c")

    new = GraphData()
    new.add_node("f1", NodeLabel.FILE, path="a.c")
    new.add_node("f2", NodeLabel.FILE, path="b.c")

    diff = old.diff(new)
    assert len(diff.nodes_added) == 1
    assert diff.nodes_added[0].id == "f2"
    assert not diff.nodes_removed
    assert diff.has_changes


def test_diff_removed_nodes():
    old = GraphData()
    old.add_node("f1", NodeLabel.FILE, path="a.c")
    old.add_node("f2", NodeLabel.FILE, path="b.c")

    new = GraphData()
    new.add_node("f1", NodeLabel.FILE, path="a.c")

    diff = old.diff(new)
    assert len(diff.nodes_removed) == 1
    assert diff.nodes_removed[0].id == "f2"
    assert not diff.nodes_added


def test_diff_modified_nodes():
    old = GraphData()
    old.add_node("f1", NodeLabel.FILE, path="a.c", size=100)

    new = GraphData()
    new.add_node("f1", NodeLabel.FILE, path="a.c", size=200)

    diff = old.diff(new)
    assert len(diff.nodes_modified) == 1
    change = diff.nodes_modified[0]
    assert change.node_id == "f1"
    assert change.changed_properties["size"] == (100, 200)
    assert diff.has_changes


def test_diff_edges_added_removed():
    old = GraphData()
    old.add_node("f1", NodeLabel.FILE, path="a.c")
    old.add_node("fn1", NodeLabel.FUNCTION, name="main")
    old.add_edge("f1", "fn1", EdgeType.CONTAINS)

    new = GraphData()
    new.add_node("f1", NodeLabel.FILE, path="a.c")
    new.add_node("fn1", NodeLabel.FUNCTION, name="main")
    new.add_node("fn2", NodeLabel.FUNCTION, name="helper")
    new.add_edge("f1", "fn2", EdgeType.CONTAINS)

    diff = old.diff(new)
    assert len(diff.edges_added) == 1
    assert diff.edges_added[0].target_id == "fn2"
    assert len(diff.edges_removed) == 1
    assert diff.edges_removed[0].target_id == "fn1"


def test_diff_no_changes():
    g = GraphData()
    g.add_node("f1", NodeLabel.FILE, path="a.c")
    g.add_edge("f1", "fn1", EdgeType.CONTAINS)

    # Same graph
    g2 = GraphData()
    g2.add_node("f1", NodeLabel.FILE, path="a.c")
    g2.add_edge("f1", "fn1", EdgeType.CONTAINS)

    diff = g.diff(g2)
    assert not diff.has_changes
    assert diff.summary() == {
        "nodes_added": 0,
        "nodes_removed": 0,
        "nodes_modified": 0,
        "edges_added": 0,
        "edges_removed": 0,
    }


def test_diff_summary_counts():
    old = GraphData()
    old.add_node("f1", NodeLabel.FILE, path="a.c")
    old.add_node("f2", NodeLabel.FILE, path="b.c")
    old.add_edge("f1", "f2", EdgeType.IMPORTS)

    new = GraphData()
    new.add_node("f1", NodeLabel.FILE, path="a.c", size=999)
    new.add_node("f3", NodeLabel.FILE, path="c.c")

    diff = old.diff(new)
    s = diff.summary()
    assert s["nodes_added"] == 1   # f3
    assert s["nodes_removed"] == 1  # f2
    assert s["nodes_modified"] == 1  # f1 (size changed)
    assert s["edges_removed"] == 1  # f1→f2 IMPORTS
    assert s["edges_added"] == 0

