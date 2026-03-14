"""Process tracing enrichment — traces execution flows from entry points."""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from archgraph.config import DANGEROUS_SINKS, INPUT_SOURCES
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

logger = logging.getLogger(__name__)

# Entry point patterns by language
_ENTRY_PATTERNS: dict[str, list[str]] = {
    "c": ["main"],
    "cpp": ["main"],
    "rust": ["main"],
    "go": ["main", "init"],
    "java": ["main"],
    "javascript": ["main", "app", "server", "index"],
    "typescript": ["main", "app", "server", "index"],
    "kotlin": ["main"],
    "swift": ["main"],
}


class ProcessTracer:
    """Traces execution flows from entry points through call chains."""

    def __init__(self, max_depth: int = 10) -> None:
        self._max_depth = max_depth

    def enrich(self, graph: GraphData) -> int:
        """Detect execution processes and add Process nodes + PARTICIPATES_IN edges.

        Returns number of processes found.
        """
        # Build call graph
        call_graph = nx.DiGraph()
        func_nodes: dict[str, Any] = {}

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION:
                func_nodes[node.id] = node
                call_graph.add_node(node.id)

        for edge in graph.edges:
            if edge.type == EdgeType.CALLS:
                if edge.source_id in call_graph and edge.target_id in call_graph:
                    call_graph.add_edge(edge.source_id, edge.target_id)

        if call_graph.number_of_nodes() == 0:
            return 0

        # Find entry points
        entry_points = self._find_entry_points(func_nodes, graph)

        if not entry_points:
            logger.info("No entry points found, skipping process tracing")
            return 0

        # Trace processes from each entry point
        process_count = 0
        for entry_id in entry_points:
            if entry_id not in call_graph:
                continue

            # BFS trace
            trace = self._trace_flow(call_graph, entry_id)
            if len(trace) < 2:
                continue

            process_id = f"process:{entry_id}"
            entry_node = func_nodes[entry_id]
            entry_name = entry_node.properties.get("name", "unknown")
            lang = entry_node.properties.get("file", "").split(".")[-1] if entry_node.properties.get("file") else ""

            # Determine process type
            process_type = self._classify_process(trace, func_nodes)

            graph.add_node(
                process_id,
                NodeLabel.PROCESS,
                name=f"{entry_name}_flow",
                entry_point=entry_name,
                depth=len(trace),
                type=process_type,
                step_count=len(trace),
            )

            # PARTICIPATES_IN edge: Function → Process (with step order)
            for step_idx, func_id in enumerate(trace):
                graph.add_edge(
                    func_id, process_id, EdgeType.PARTICIPATES_IN, step=step_idx
                )

            process_count += 1

        logger.info(
            "Traced %d processes from %d entry points",
            process_count,
            len(entry_points),
        )
        return process_count

    def _find_entry_points(
        self, func_nodes: dict[str, Any], graph: GraphData
    ) -> list[str]:
        """Find entry point functions (main, init, etc.)."""
        entry_ids: list[str] = []

        for func_id, node in func_nodes.items():
            name = node.properties.get("name", "")
            file_path = node.properties.get("file", "")

            # Check if name matches entry patterns
            lang = self._detect_lang(file_path)
            patterns = _ENTRY_PATTERNS.get(lang, ["main"])

            if name in patterns:
                entry_ids.append(func_id)
                continue

            # Check if it's an exported function with no callers (potential entry)
            is_exported = node.properties.get("is_exported", False)
            if is_exported and name and not self._has_callers(func_id, graph):
                entry_ids.append(func_id)

        return entry_ids

    def _has_callers(self, func_id: str, graph: GraphData) -> bool:
        """Check if a function has any callers."""
        for edge in graph.edges:
            if edge.type == EdgeType.CALLS and edge.target_id == func_id:
                return True
        return False

    def _trace_flow(self, call_graph: nx.DiGraph, start: str) -> list[str]:
        """BFS trace from entry point through call graph."""
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start, 0)]
        trace: list[str] = []

        while queue:
            node_id, depth = queue.pop(0)
            if node_id in visited or depth > self._max_depth:
                continue

            visited.add(node_id)
            trace.append(node_id)

            for successor in call_graph.successors(node_id):
                if successor not in visited:
                    queue.append((successor, depth + 1))

        return trace

    def _classify_process(
        self, trace: list[str], func_nodes: dict[str, Any]
    ) -> str:
        """Classify a process by what it touches."""
        has_input = False
        has_sink = False

        for func_id in trace:
            node = func_nodes.get(func_id)
            if not node:
                continue
            name = node.properties.get("name", "")
            if name in INPUT_SOURCES or node.properties.get("is_input_source"):
                has_input = True
            if name in DANGEROUS_SINKS or node.properties.get("is_dangerous_sink"):
                has_sink = True

        if has_input and has_sink:
            return "data_flow"  # Input → Sink
        if has_input:
            return "input_handler"
        if has_sink:
            return "sink_caller"
        return "computation"

    def _detect_lang(self, file_path: str) -> str:
        """Detect language from file extension."""
        ext_map = {
            ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
            ".rs": "rust", ".go": "go", ".java": "java",
            ".js": "javascript", ".ts": "typescript",
            ".kt": "kotlin", ".swift": "swift",
        }
        for ext, lang in ext_map.items():
            if file_path.endswith(ext):
                return lang
        return ""
