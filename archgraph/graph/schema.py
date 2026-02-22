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
    HAS_ANNOTATION = "HAS_ANNOTATION"
    COMPILED_WITH = "COMPILED_WITH"
    # Clang deep analysis
    DATA_FLOWS_TO = "DATA_FLOWS_TO"
    TAINTS = "TAINTS"
    BRANCHES_TO = "BRANCHES_TO"
