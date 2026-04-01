"""SCIP-based call resolution — compiler-backed accuracy."""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Protocol, runtime_checkable

from archgraph.extractors import scip_pb2
from archgraph.graph.schema import Edge, GraphData, Node, NodeLabel, EdgeType

logger = logging.getLogger(__name__)


# ── Indexer Protocol & Registry ───────────────────────────────────────────


@runtime_checkable
class ScipIndexer(Protocol):
    """Interface for per-language SCIP indexers."""

    language: str

    def install(self, repo_path: Path) -> bool: ...
    def index(self, repo_path: Path) -> Path | None: ...


class TypeScriptIndexer:
    """SCIP indexer for TypeScript/JavaScript using @sourcegraph/scip-typescript."""

    language = "typescript"

    def install(self, repo_path: Path) -> bool:
        if not shutil.which("npm"):
            logger.warning("npm not found — cannot install scip-typescript")
            return False
        if self._is_available(repo_path):
            return True

        logger.info("Installing @sourcegraph/scip-typescript...")
        result = subprocess.run(
            ["npm", "install", "--save-dev", "@sourcegraph/scip-typescript"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 and self._is_available(repo_path):
            return True

        logger.info("Repo-local install failed, trying global...")
        subprocess.run(
            ["npm", "install", "-g", "@sourcegraph/scip-typescript"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return self._is_available(repo_path)

    def index(self, repo_path: Path) -> Path | None:
        output_dir = repo_path / ".archgraph"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / "index.scip"

        cmd = ["npx", "scip-typescript", "index", "--output", str(output_path)]
        if not (repo_path / "tsconfig.json").exists():
            cmd.append("--infer-tsconfig")

        logger.info("Running scip-typescript index...")
        try:
            result = subprocess.run(
                cmd,
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            logger.warning("scip-typescript timed out")
            return None

        if result.returncode != 0:
            logger.warning("scip-typescript failed: %s", result.stderr[:500])
            return None
        if output_path.exists():
            return output_path
        return None

    def _is_available(self, repo_path: Path) -> bool:
        try:
            result = subprocess.run(
                ["npx", "scip-typescript", "--version"],
                cwd=str(repo_path),
                capture_output=True,
                timeout=30,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False


# TODO: class PythonIndexer(ScipIndexer): ...   # pip install scip-python
# TODO: class JavaIndexer(ScipIndexer): ...     # scip-java JAR download
# TODO: class RustIndexer(ScipIndexer): ...     # rust-analyzer --scip
# TODO: class GoIndexer(ScipIndexer): ...       # go install scip-go
# TODO: class ClangIndexer(ScipIndexer): ...    # scip-clang binary


INDEXER_REGISTRY: dict[str, type[TypeScriptIndexer]] = {
    "typescript": TypeScriptIndexer,
    "javascript": TypeScriptIndexer,
    # "python": PythonIndexer,    # TODO
    # "java": JavaIndexer,        # TODO
    # "kotlin": JavaIndexer,      # TODO
    # "rust": RustIndexer,        # TODO
    # "go": GoIndexer,            # TODO
    # "c": ClangIndexer,          # TODO
    # "cpp": ClangIndexer,        # TODO
}


# ── SCIP Parsing ─────────────────────────────────────────────────────────


def _extract_name_from_symbol(symbol: str) -> str:
    """Extract human-readable name from SCIP symbol string.

    Examples:
        "npm pkg `src/utils.ts`/add()." → "add"
        "npm pkg `src/a.ts`/MyClass#method()." → "method"
    """
    name = symbol.rstrip(".")
    for sep in ("#", "/"):
        if sep in name:
            name = name.rsplit(sep, 1)[-1]
    name = name.rstrip("()")
    return name


def parse_scip_index(
    data: bytes,
) -> tuple[dict[str, tuple[str, int, str]], list[tuple[str, int, str]]]:
    """Parse serialized SCIP index into definitions and references.

    Returns:
        sym_to_def: {symbol_string: (file, line, name)}
        references: [(file, line, symbol_string)]
    """
    idx = scip_pb2.Index()
    idx.ParseFromString(data)

    sym_to_def: dict[str, tuple[str, int, str]] = {}
    references: list[tuple[str, int, str]] = []

    for doc in idx.documents:
        file_path = doc.relative_path.replace("\\", "/")
        for occ in doc.occurrences:
            line = occ.range[0] if occ.range else 0
            if occ.symbol_roles & 1:  # Definition
                name = _extract_name_from_symbol(occ.symbol)
                sym_to_def[occ.symbol] = (file_path, line, name)
            else:
                references.append((file_path, line, occ.symbol))

    return sym_to_def, references


# ── ScipResolver ─────────────────────────────────────────────────────────


class ScipResolver:
    """SCIP-based call resolution — compiler-backed accuracy."""

    def __init__(self, graph: GraphData, repo_path: Path, languages: list[str]) -> None:
        self._graph = graph
        self._repo_path = repo_path
        self._languages = languages
        self._build_func_ranges()

    def _build_func_ranges(self) -> None:
        """Build file → sorted [(line_start, line_end, node)] for caller detection."""
        self._func_ranges: dict[str, list[tuple[int, int, Node]]] = defaultdict(list)

        for node in self._graph.nodes:
            if node.label == NodeLabel.FUNCTION and not node.id.startswith("funcref:"):
                file_path = node.properties.get("file", "").replace("\\", "/")
                line_start = node.properties.get("line_start", 0)
                line_end = node.properties.get("line_end", line_start)
                if file_path and line_start:
                    self._func_ranges[file_path].append((line_start, line_end, node))

        for funcs in self._func_ranges.values():
            funcs.sort(key=lambda t: t[0])

    def _find_enclosing_function(self, file_path: str, line: int) -> Node | None:
        """Find which function encloses a given line number."""
        file_path = file_path.replace("\\", "/")
        funcs = self._func_ranges.get(file_path, [])
        best: Node | None = None
        best_start = -1
        for start, end, node in funcs:
            if start <= line <= end and start > best_start:
                best = node
                best_start = start
        return best

    def _match_target_node(self, file_path: str, line: int, name: str) -> Node | None:
        """Find the func: node matching a SCIP definition."""
        file_path = file_path.replace("\\", "/")
        funcs = self._func_ranges.get(file_path, [])
        # SCIP lines are 0-indexed, our nodes are 1-indexed
        target_line = line + 1
        # Exact name + line match first
        for start, _end, node in funcs:
            if node.properties.get("name") == name and start == target_line:
                return node
        # Fallback: name match, closest line
        candidates = [
            (abs(start - target_line), node)
            for start, _end, node in funcs
            if node.properties.get("name") == name
        ]
        if candidates:
            candidates.sort(key=lambda t: t[0])
            return candidates[0][1]
        return None

    def _apply_scip_data(self, scip_data: bytes, scip_languages: set[str]) -> int:
        """Parse SCIP index and generate CALLS edges. Returns edges created."""
        sym_to_def, references = parse_scip_index(scip_data)

        created = 0
        seen_edges: set[tuple[str, str]] = set()

        for ref_file, ref_line, symbol in references:
            if symbol not in sym_to_def:
                continue

            def_file, def_line, def_name = sym_to_def[symbol]

            # +1 because SCIP is 0-indexed, our func ranges are 1-indexed
            caller = self._find_enclosing_function(ref_file, ref_line + 1)
            if caller is None:
                continue

            target = self._match_target_node(def_file, def_line, def_name)
            if target is None:
                continue

            if caller.id == target.id:
                continue

            edge_key = (caller.id, target.id)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            self._graph.add_edge(
                caller.id, target.id, EdgeType.CALLS,
                resolved=True, source="scip",
            )
            created += 1

        return created

    def _cleanup_funcref(self, scip_languages: set[str]) -> None:
        """Remove funcref: nodes and edges for SCIP-covered languages."""
        if not scip_languages:
            return

        from archgraph.config import EXTENSION_MAP

        scip_covered_files: set[str] = set()
        for node in self._graph.nodes:
            if node.label == NodeLabel.FILE:
                path = node.properties.get("path", "")
                ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
                lang = EXTENSION_MAP.get(ext.lower(), "")
                if lang in scip_languages:
                    scip_covered_files.add(path.replace("\\", "/"))

        # Build caller_id → file lookup
        node_file: dict[str, str] = {}
        for n in self._graph.nodes:
            if n.label == NodeLabel.FUNCTION:
                node_file[n.id] = n.properties.get("file", "").replace("\\", "/")

        # Remove funcref CALLS edges from SCIP-covered callers
        self._graph.edges = [
            e for e in self._graph.edges
            if not (
                e.type == EdgeType.CALLS
                and e.target_id.startswith("funcref:")
                and node_file.get(e.source_id, "") in scip_covered_files
            )
        ]

        # Remove orphaned funcref: nodes
        referenced_ids = (
            {e.target_id for e in self._graph.edges}
            | {e.source_id for e in self._graph.edges}
        )
        self._graph.nodes = [
            n for n in self._graph.nodes
            if not n.id.startswith("funcref:") or n.id in referenced_ids
        ]

    def resolve(self) -> GraphData:
        """Run SCIP indexers, apply results, fallback to heuristic for uncovered languages."""
        scip_languages: set[str] = set()
        scip_data: bytes | None = None

        for lang in self._languages:
            indexer_cls = INDEXER_REGISTRY.get(lang)
            if indexer_cls is None:
                continue
            # Avoid running the same indexer twice (TS/JS share one)
            if lang in scip_languages:
                continue

            indexer = indexer_cls()
            if not indexer.install(self._repo_path):
                logger.warning("Failed to install SCIP indexer for %s", lang)
                continue

            scip_path = indexer.index(self._repo_path)
            if scip_path is None:
                logger.warning("SCIP indexing failed for %s, falling back to heuristic", lang)
                continue

            scip_data = scip_path.read_bytes()
            scip_languages.add(lang)
            if lang in ("typescript", "javascript"):
                scip_languages.add("typescript")
                scip_languages.add("javascript")

        if scip_data and scip_languages:
            self._cleanup_funcref(scip_languages)
            count = self._apply_scip_data(scip_data, scip_languages)
            logger.info(
                "SCIP: created %d resolved CALLS edges for %s",
                count, ", ".join(sorted(scip_languages)),
            )

        # Fallback: heuristic for non-SCIP languages
        uncovered = [l for l in self._languages if l not in scip_languages]
        if uncovered:
            from archgraph.extractors.call_resolver import CallResolver
            logger.info("Heuristic fallback for: %s", ", ".join(uncovered))
            CallResolver(self._graph).resolve()

        return self._graph
