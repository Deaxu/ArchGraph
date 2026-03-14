"""Graph schema — Node and Edge definitions for the code knowledge graph."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Node:
    """A node in the code graph."""

    id: str  # Unique identifier (e.g., "file:/path/to/file.c", "func:module::foo")
    label: str  # Node label (e.g., "Function", "File", "Class")
    properties: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Node):
            return NotImplemented
        return self.id == other.id


@dataclass
class Edge:
    """An edge (relationship) in the code graph."""

    source_id: str  # Source node id
    target_id: str  # Target node id
    type: str  # Relationship type (e.g., "CALLS", "CONTAINS")
    properties: dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash((self.source_id, self.target_id, self.type))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Edge):
            return NotImplemented
        return (
            self.source_id == other.source_id
            and self.target_id == other.target_id
            and self.type == other.type
        )


@dataclass
class GraphData:
    """Container for extracted graph nodes and edges."""

    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, id: str, label: str, **properties: Any) -> Node:
        node = Node(id=id, label=label, properties=properties)
        self.nodes.append(node)
        return node

    def add_edge(self, source_id: str, target_id: str, type: str, **properties: Any) -> Edge:
        edge = Edge(source_id=source_id, target_id=target_id, type=type, properties=properties)
        self.edges.append(edge)
        return edge

    def merge(self, other: GraphData) -> None:
        """Merge another GraphData into this one."""
        self.nodes.extend(other.nodes)
        self.edges.extend(other.edges)

    def deduplicate(self) -> None:
        """Remove duplicate nodes and edges."""
        seen_nodes: dict[str, Node] = {}
        for node in self.nodes:
            if node.id in seen_nodes:
                # Merge properties — later values overwrite
                seen_nodes[node.id].properties.update(node.properties)
            else:
                seen_nodes[node.id] = node
        self.nodes = list(seen_nodes.values())

        seen_edges: set[tuple[str, str, str]] = set()
        unique_edges: list[Edge] = []
        for edge in self.edges:
            key = (edge.source_id, edge.target_id, edge.type)
            if key not in seen_edges:
                seen_edges.add(key)
                unique_edges.append(edge)
        self.edges = unique_edges

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def stats(self) -> dict[str, dict[str, int]]:
        """Return counts per node label and edge type."""
        node_counts: dict[str, int] = {}
        for node in self.nodes:
            node_counts[node.label] = node_counts.get(node.label, 0) + 1

        edge_counts: dict[str, int] = {}
        for edge in self.edges:
            edge_counts[edge.type] = edge_counts.get(edge.type, 0) + 1

        return {"nodes": node_counts, "edges": edge_counts}

    def diff(self, newer: GraphData) -> GraphDiff:
        """Compute the difference between this graph (old) and *newer*.

        Returns a GraphDiff with added/removed/modified nodes and edges.
        """
        # Build id→Node maps
        old_map: dict[str, Node] = {n.id: n for n in self.nodes}
        new_map: dict[str, Node] = {n.id: n for n in newer.nodes}

        old_ids = set(old_map.keys())
        new_ids = set(new_map.keys())

        # Added / removed nodes
        nodes_added = [new_map[nid] for nid in sorted(new_ids - old_ids)]
        nodes_removed = [old_map[nid] for nid in sorted(old_ids - new_ids)]

        # Modified nodes — same id but different properties
        nodes_modified: list[NodeChange] = []
        for nid in sorted(old_ids & new_ids):
            old_node = old_map[nid]
            new_node = new_map[nid]
            changed: dict[str, tuple[Any, Any]] = {}
            all_keys = set(old_node.properties.keys()) | set(new_node.properties.keys())
            for key in sorted(all_keys):
                old_val = old_node.properties.get(key)
                new_val = new_node.properties.get(key)
                if old_val != new_val:
                    changed[key] = (old_val, new_val)
            if changed:
                nodes_modified.append(
                    NodeChange(node_id=nid, label=new_node.label, changed_properties=changed)
                )

        # Edge diff — by (source, target, type) identity
        old_edge_set = {(e.source_id, e.target_id, e.type) for e in self.edges}
        new_edge_set = {(e.source_id, e.target_id, e.type) for e in newer.edges}

        new_edge_map = {(e.source_id, e.target_id, e.type): e for e in newer.edges}
        old_edge_map = {(e.source_id, e.target_id, e.type): e for e in self.edges}

        edges_added = [new_edge_map[k] for k in sorted(new_edge_set - old_edge_set)]
        edges_removed = [old_edge_map[k] for k in sorted(old_edge_set - new_edge_set)]

        return GraphDiff(
            nodes_added=nodes_added,
            nodes_removed=nodes_removed,
            nodes_modified=nodes_modified,
            edges_added=edges_added,
            edges_removed=edges_removed,
        )


# --- Node label constants ---

class NodeLabel:
    FILE = "File"
    MODULE = "Module"
    FUNCTION = "Function"
    CLASS = "Class"
    STRUCT = "Struct"
    FIELD = "Field"
    ENUM = "Enum"
    INTERFACE = "Interface"
    TYPE_ALIAS = "TypeAlias"
    MACRO = "Macro"
    VARIABLE = "Variable"
    PARAMETER = "Parameter"
    COMMIT = "Commit"
    AUTHOR = "Author"
    TAG = "Tag"
    DEPENDENCY = "Dependency"
    SECURITY_FIX = "SecurityFix"
    ANNOTATION = "Annotation"
    BUILD_CONFIG = "BuildConfig"
    BASIC_BLOCK = "BasicBlock"
    VULNERABILITY = "Vulnerability"
    CLUSTER = "Cluster"
    PROCESS = "Process"


class EdgeType:
    # Structural
    CONTAINS = "CONTAINS"
    IMPORTS = "IMPORTS"
    CALLS = "CALLS"
    INSTANTIATES = "INSTANTIATES"
    INHERITS = "INHERITS"
    IMPLEMENTS = "IMPLEMENTS"
    USES_TYPE = "USES_TYPE"
    OVERRIDES = "OVERRIDES"
    EXPANDS_MACRO = "EXPANDS_MACRO"
    # Git
    MODIFIED_IN = "MODIFIED_IN"
    AUTHORED_BY = "AUTHORED_BY"
    TAGGED_AS = "TAGGED_AS"
    PARENT = "PARENT"
    # Security / Dependency
    DEPENDS_ON = "DEPENDS_ON"
    FIXED_BY = "FIXED_BY"
    AFFECTS = "AFFECTS"
    HAS_ANNOTATION = "HAS_ANNOTATION"
    COMPILED_WITH = "COMPILED_WITH"
    # Clang deep analysis
    DATA_FLOWS_TO = "DATA_FLOWS_TO"
    TAINTS = "TAINTS"
    BRANCHES_TO = "BRANCHES_TO"
    # CVE enrichment
    AFFECTED_BY = "AFFECTED_BY"
    # Clustering & Process tracing
    BELONGS_TO = "BELONGS_TO"
    PARTICIPATES_IN = "PARTICIPATES_IN"


# ── Graph Diff ───────────────────────────────────────────────────────────────


@dataclass
class NodeChange:
    """Describes how a single node was modified between two graph snapshots."""

    node_id: str
    label: str
    changed_properties: dict[str, tuple[Any, Any]]  # prop → (old_value, new_value)


@dataclass
class GraphDiff:
    """Difference between two GraphData snapshots."""

    nodes_added: list[Node] = field(default_factory=list)
    nodes_removed: list[Node] = field(default_factory=list)
    nodes_modified: list[NodeChange] = field(default_factory=list)
    edges_added: list[Edge] = field(default_factory=list)
    edges_removed: list[Edge] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.nodes_added
            or self.nodes_removed
            or self.nodes_modified
            or self.edges_added
            or self.edges_removed
        )

    def summary(self) -> dict[str, int]:
        """Return a dict of change category → count."""
        return {
            "nodes_added": len(self.nodes_added),
            "nodes_removed": len(self.nodes_removed),
            "nodes_modified": len(self.nodes_modified),
            "edges_added": len(self.edges_added),
            "edges_removed": len(self.edges_removed),
        }

