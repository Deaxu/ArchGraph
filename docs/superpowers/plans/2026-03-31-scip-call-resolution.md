# SCIP-Based Call Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace heuristic call resolution with SCIP compiler-backed cross-references, auto-installing indexers per language, with heuristic fallback for unsupported languages.

**Architecture:** `ScipResolver` runs SCIP indexers per detected language, parses the protobuf output to build a symbol→definition map, generates CALLS edges from reference occurrences, and removes old funcref: nodes. Languages without SCIP indexers fall back to the existing `CallResolver`.

**Tech Stack:** Python 3.11+, protobuf, scip-typescript (npm), subprocess

---

## File Structure

| File | Responsibility |
|------|---------------|
| `archgraph/extractors/scip_resolver.py` (NEW) | `ScipResolver`, `ScipIndexer` protocol, `TypeScriptIndexer`, `INDEXER_REGISTRY`, SCIP parsing, CALLS edge generation |
| `archgraph/extractors/scip_pb2.py` (MOVE) | Pre-compiled SCIP protobuf (move from repo root into package) |
| `tests/test_scip_resolver.py` (NEW) | All SCIP resolution tests |
| `archgraph/graph/builder.py` (MODIFY) | Step 4.5: ScipResolver first, CallResolver fallback |

---

### Task 1: Move scip_pb2.py into package and verify import

**Files:**
- Move: `scip_pb2.py` → `archgraph/extractors/scip_pb2.py`
- Test: `tests/test_scip_resolver.py`

- [ ] **Step 1: Write test that imports scip_pb2**

Create `tests/test_scip_resolver.py`:

```python
"""Tests for SCIP-based call resolution."""

from pathlib import Path

import pytest


class TestScipProto:
    """Test that SCIP protobuf can be imported and used."""

    def test_import_scip_pb2(self):
        from archgraph.extractors import scip_pb2
        idx = scip_pb2.Index()
        assert hasattr(idx, "documents")
        assert hasattr(idx, "metadata")

    def test_create_mock_index(self):
        from archgraph.extractors import scip_pb2
        idx = scip_pb2.Index()
        doc = idx.documents.add()
        doc.relative_path = "src/main.ts"
        occ = doc.occurrences.add()
        occ.symbol = "test_symbol"
        occ.symbol_roles = 1  # Definition
        occ.range.extend([10, 0, 10, 5])
        assert len(idx.documents) == 1
        assert idx.documents[0].occurrences[0].symbol == "test_symbol"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scip_resolver.py::TestScipProto -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'archgraph.extractors.scip_pb2'`

- [ ] **Step 3: Move scip_pb2.py into the package**

```bash
cp scip_pb2.py archgraph/extractors/scip_pb2.py
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scip_resolver.py::TestScipProto -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add archgraph/extractors/scip_pb2.py tests/test_scip_resolver.py
git commit -m "feat: add SCIP protobuf to extractors package"
```

---

### Task 2: TypeScriptIndexer — install and index

**Files:**
- Create: `archgraph/extractors/scip_resolver.py`
- Test: `tests/test_scip_resolver.py`

- [ ] **Step 1: Write tests for TypeScriptIndexer**

Append to `tests/test_scip_resolver.py`:

```python
import subprocess
from unittest.mock import patch, MagicMock

from archgraph.extractors.scip_resolver import TypeScriptIndexer


class TestTypeScriptIndexer:
    """Test TypeScriptIndexer install and index methods."""

    def test_install_checks_npm(self):
        """install() returns False if npm not found."""
        with patch("shutil.which", return_value=None):
            indexer = TypeScriptIndexer()
            assert indexer.install(Path("/fake")) is False

    def test_install_runs_npm_install(self):
        """install() runs npm install when scip-typescript not found."""
        with patch("shutil.which", return_value="/usr/bin/npm"), \
             patch("subprocess.run") as mock_run:
            # First call: npx scip-typescript --version fails
            # Second call: npm install succeeds
            # Third call: npx scip-typescript --version succeeds
            mock_run.side_effect = [
                MagicMock(returncode=1),  # version check fails
                MagicMock(returncode=0),  # npm install succeeds
                MagicMock(returncode=0),  # version check passes
            ]
            indexer = TypeScriptIndexer()
            result = indexer.install(Path("/fake"))
            assert result is True
            # Verify npm install was called
            install_call = mock_run.call_args_list[1]
            assert "@sourcegraph/scip-typescript" in " ".join(install_call[0][0])

    def test_index_returns_path_on_success(self, tmp_path):
        """index() returns .scip path when indexer succeeds."""
        scip_output = tmp_path / ".archgraph" / "index.scip"
        scip_output.parent.mkdir(parents=True)
        scip_output.write_bytes(b"fake scip data")
        (tmp_path / "tsconfig.json").write_text("{}")

        with patch("subprocess.run", return_value=MagicMock(returncode=0)):
            indexer = TypeScriptIndexer()
            result = indexer.index(tmp_path)
            assert result is not None

    def test_index_returns_none_on_failure(self, tmp_path):
        """index() returns None when indexer fails."""
        (tmp_path / "tsconfig.json").write_text("{}")
        with patch("subprocess.run", return_value=MagicMock(returncode=1, stderr="error")):
            indexer = TypeScriptIndexer()
            result = indexer.index(tmp_path)
            assert result is None

    def test_index_infers_tsconfig(self, tmp_path):
        """index() uses --infer-tsconfig when tsconfig.json is missing."""
        scip_output = tmp_path / ".archgraph" / "index.scip"
        scip_output.parent.mkdir(parents=True)
        scip_output.write_bytes(b"fake")

        with patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_run:
            indexer = TypeScriptIndexer()
            indexer.index(tmp_path)
            cmd = mock_run.call_args[0][0]
            assert "--infer-tsconfig" in cmd
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scip_resolver.py::TestTypeScriptIndexer -v`
Expected: FAIL — `ImportError: cannot import name 'TypeScriptIndexer'`

- [ ] **Step 3: Create scip_resolver.py with TypeScriptIndexer**

Create `archgraph/extractors/scip_resolver.py`:

```python
"""SCIP-based call resolution — compiler-backed accuracy."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ── Indexer Protocol & Registry ───────────────────────────────────────────


@runtime_checkable
class ScipIndexer(Protocol):
    """Interface for per-language SCIP indexers."""

    language: str

    def install(self, repo_path: Path) -> bool:
        """Ensure the indexer is available. Auto-install if needed. Returns True on success."""
        ...

    def index(self, repo_path: Path) -> Path | None:
        """Run the indexer. Returns path to .scip file, or None on failure."""
        ...


class TypeScriptIndexer:
    """SCIP indexer for TypeScript/JavaScript using @sourcegraph/scip-typescript."""

    language = "typescript"

    def install(self, repo_path: Path) -> bool:
        if not shutil.which("npm"):
            logger.warning("npm not found — cannot install scip-typescript")
            return False

        # Check if already available
        if self._is_available(repo_path):
            return True

        # Try repo-local install
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

        # Fallback: global install
        logger.info("Repo-local install failed, trying global...")
        result = subprocess.run(
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
        result = subprocess.run(
            cmd,
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=300,
        )
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scip_resolver.py::TestTypeScriptIndexer -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add archgraph/extractors/scip_resolver.py tests/test_scip_resolver.py
git commit -m "feat: add TypeScriptIndexer with auto-install"
```

---

### Task 3: SCIP Parsing — symbol→definition map and caller detection

**Files:**
- Modify: `archgraph/extractors/scip_resolver.py`
- Test: `tests/test_scip_resolver.py`

- [ ] **Step 1: Write tests for SCIP parsing**

Append to `tests/test_scip_resolver.py`:

```python
from archgraph.extractors.scip_resolver import ScipResolver, parse_scip_index
from archgraph.extractors import scip_pb2
from archgraph.graph.schema import GraphData, Node, NodeLabel, EdgeType


def _make_scip_index(documents: list[dict]) -> bytes:
    """Helper: create a serialized SCIP index from a simple dict structure."""
    idx = scip_pb2.Index()
    for doc_dict in documents:
        doc = idx.documents.add()
        doc.relative_path = doc_dict["path"]
        for occ_dict in doc_dict.get("occurrences", []):
            occ = doc.occurrences.add()
            occ.symbol = occ_dict["symbol"]
            occ.symbol_roles = occ_dict.get("roles", 0)
            occ.range.extend(occ_dict.get("range", [0, 0, 0, 0]))
    return idx.SerializeToString()


class TestScipParsing:
    """Test parse_scip_index builds correct sym_to_def map."""

    def test_definitions_extracted(self):
        data = _make_scip_index([{
            "path": "src/utils.ts",
            "occurrences": [
                {"symbol": "npm pkg `src/utils.ts`/add().", "roles": 1, "range": [5, 0, 5, 3]},
                {"symbol": "npm pkg `src/utils.ts`/subtract().", "roles": 1, "range": [10, 0, 10, 8]},
            ],
        }])
        sym_to_def, references = parse_scip_index(data)
        assert len(sym_to_def) == 2
        assert sym_to_def["npm pkg `src/utils.ts`/add()."] == ("src/utils.ts", 5, "add")
        assert sym_to_def["npm pkg `src/utils.ts`/subtract()."] == ("src/utils.ts", 10, "subtract")

    def test_references_collected(self):
        data = _make_scip_index([{
            "path": "src/app.ts",
            "occurrences": [
                {"symbol": "npm pkg `src/utils.ts`/add().", "roles": 0, "range": [3, 10, 3, 13]},
            ],
        }])
        sym_to_def, references = parse_scip_index(data)
        assert len(references) == 1
        assert references[0] == ("src/app.ts", 3, "npm pkg `src/utils.ts`/add().")

    def test_name_extraction_from_symbol(self):
        data = _make_scip_index([{
            "path": "src/a.ts",
            "occurrences": [
                {"symbol": "npm @scope/pkg 1.0.0 `src/a.ts`/MyClass#method().", "roles": 1, "range": [1, 0, 1, 6]},
            ],
        }])
        sym_to_def, _ = parse_scip_index(data)
        sym = "npm @scope/pkg 1.0.0 `src/a.ts`/MyClass#method()."
        assert sym_to_def[sym][2] == "method"


class TestCallerDetection:
    """Test finding which function encloses a reference line."""

    def test_reference_inside_function(self):
        graph = GraphData()
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=1, line_end=10)
        graph.add_node("func:src/app.ts:helper:15", NodeLabel.FUNCTION,
                        name="helper", file="src/app.ts", line_start=15, line_end=20)

        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        caller = resolver._find_enclosing_function("src/app.ts", 5)
        assert caller is not None
        assert caller.id == "func:src/app.ts:main:1"

    def test_reference_in_second_function(self):
        graph = GraphData()
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=1, line_end=10)
        graph.add_node("func:src/app.ts:helper:15", NodeLabel.FUNCTION,
                        name="helper", file="src/app.ts", line_start=15, line_end=20)

        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        caller = resolver._find_enclosing_function("src/app.ts", 17)
        assert caller is not None
        assert caller.id == "func:src/app.ts:helper:15"

    def test_reference_outside_functions(self):
        graph = GraphData()
        graph.add_node("func:src/app.ts:main:5", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=5, line_end=10)

        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        caller = resolver._find_enclosing_function("src/app.ts", 1)
        assert caller is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scip_resolver.py::TestScipParsing tests/test_scip_resolver.py::TestCallerDetection -v`
Expected: FAIL — `ImportError: cannot import name 'parse_scip_index'`

- [ ] **Step 3: Implement parse_scip_index and _find_enclosing_function**

Add to `archgraph/extractors/scip_resolver.py` after the INDEXER_REGISTRY:

```python
from archgraph.graph.schema import Edge, GraphData, Node, NodeLabel, EdgeType
from archgraph.extractors import scip_pb2


def _extract_name_from_symbol(symbol: str) -> str:
    """Extract human-readable name from SCIP symbol string.

    Examples:
        "npm pkg `src/utils.ts`/add()." → "add"
        "npm pkg `src/a.ts`/MyClass#method()." → "method"
    """
    name = symbol.rstrip(".")
    # Take last segment after / or #
    for sep in ("#", "/"):
        if sep in name:
            name = name.rsplit(sep, 1)[-1]
    # Strip trailing () for functions/methods
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


class ScipResolver:
    """SCIP-based call resolution — compiler-backed accuracy."""

    def __init__(self, graph: GraphData, repo_path: Path, languages: list[str]) -> None:
        self._graph = graph
        self._repo_path = repo_path
        self._languages = languages
        self._build_func_ranges()

    def _build_func_ranges(self) -> None:
        """Build file → sorted [(line_start, line_end, node)] index for caller detection."""
        from collections import defaultdict
        self._func_ranges: dict[str, list[tuple[int, int, Node]]] = defaultdict(list)

        for node in self._graph.nodes:
            if node.label == NodeLabel.FUNCTION and not node.id.startswith("funcref:"):
                file_path = node.properties.get("file", "").replace("\\", "/")
                line_start = node.properties.get("line_start", 0)
                line_end = node.properties.get("line_end", line_start)
                if file_path and line_start:
                    self._func_ranges[file_path].append((line_start, line_end, node))

        # Sort by line_start for binary search
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

    def resolve(self) -> GraphData:
        """Placeholder — full resolution in Task 4."""
        return self._graph
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scip_resolver.py::TestScipParsing tests/test_scip_resolver.py::TestCallerDetection -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add archgraph/extractors/scip_resolver.py tests/test_scip_resolver.py
git commit -m "feat: add SCIP index parsing and caller detection"
```

---

### Task 4: ScipResolver.resolve() — full resolution + cleanup

**Files:**
- Modify: `archgraph/extractors/scip_resolver.py`
- Test: `tests/test_scip_resolver.py`

- [ ] **Step 1: Write tests for edge generation and cleanup**

Append to `tests/test_scip_resolver.py`:

```python
class TestEdgeGeneration:
    """Test that SCIP references produce correct CALLS edges."""

    def test_scip_creates_resolved_edge(self):
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("file:src/utils.ts", NodeLabel.FILE, path="src/utils.ts")
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=1, line_end=10)
        graph.add_node("func:src/utils.ts:add:5", NodeLabel.FUNCTION,
                        name="add", file="src/utils.ts", line_start=5, line_end=8)
        # Old funcref edge from tree-sitter
        graph.add_node("funcref:add", NodeLabel.FUNCTION, name="add")
        graph.add_edge("func:src/app.ts:main:1", "funcref:add", EdgeType.CALLS)

        scip_data = _make_scip_index([
            {
                "path": "src/utils.ts",
                "occurrences": [
                    {"symbol": "pkg `src/utils.ts`/add().", "roles": 1, "range": [5, 0, 5, 3]},
                ],
            },
            {
                "path": "src/app.ts",
                "occurrences": [
                    {"symbol": "pkg `src/utils.ts`/add().", "roles": 0, "range": [3, 10, 3, 13]},
                ],
            },
        ])

        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        resolver._apply_scip_data(scip_data, {"typescript", "javascript"})

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        resolved = [e for e in calls if e.properties.get("resolved")]
        assert len(resolved) >= 1
        assert resolved[0].target_id == "func:src/utils.ts:add:5"
        assert resolved[0].properties.get("source") == "scip"

    def test_scip_self_definitions_skipped(self):
        """Definitions should not produce CALLS edges (only references)."""
        graph = GraphData()
        graph.add_node("func:src/a.ts:foo:1", NodeLabel.FUNCTION,
                        name="foo", file="src/a.ts", line_start=1, line_end=5)

        scip_data = _make_scip_index([{
            "path": "src/a.ts",
            "occurrences": [
                {"symbol": "pkg `src/a.ts`/foo().", "roles": 1, "range": [1, 0, 1, 3]},
            ],
        }])

        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        resolver._apply_scip_data(scip_data, {"typescript"})

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) == 0


class TestFuncrefCleanup:
    """Test that old funcref nodes/edges are removed for SCIP-covered languages."""

    def test_funcref_removed_for_scip_languages(self):
        graph = GraphData()
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/app.ts", line_start=1, line_end=10)
        graph.add_node("funcref:foo", NodeLabel.FUNCTION, name="foo")
        graph.add_node("funcref:bar", NodeLabel.FUNCTION, name="bar")
        graph.add_edge("func:src/app.ts:main:1", "funcref:foo", EdgeType.CALLS)
        graph.add_edge("func:src/app.ts:main:1", "funcref:bar", EdgeType.CALLS)

        resolver = ScipResolver(graph, Path("/fake"), ["typescript"])
        resolver._cleanup_funcref({"typescript", "javascript"})

        funcref_nodes = [n for n in graph.nodes if n.id.startswith("funcref:")]
        funcref_edges = [e for e in graph.edges if e.target_id.startswith("funcref:")]
        assert len(funcref_nodes) == 0
        assert len(funcref_edges) == 0

    def test_non_scip_funcref_preserved(self):
        """funcref edges from non-SCIP languages stay."""
        graph = GraphData()
        graph.add_node("func:src/main.c:main:1", NodeLabel.FUNCTION,
                        name="main", file="src/main.c", line_start=1, line_end=10)
        graph.add_node("funcref:printf", NodeLabel.FUNCTION, name="printf")
        graph.add_edge("func:src/main.c:main:1", "funcref:printf", EdgeType.CALLS)

        resolver = ScipResolver(graph, Path("/fake"), ["c"])
        # SCIP covered languages is empty for C (no indexer)
        resolver._cleanup_funcref(set())

        funcref_nodes = [n for n in graph.nodes if n.id.startswith("funcref:")]
        assert len(funcref_nodes) == 1  # preserved
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scip_resolver.py::TestEdgeGeneration tests/test_scip_resolver.py::TestFuncrefCleanup -v`
Expected: FAIL — `_apply_scip_data` not defined

- [ ] **Step 3: Implement _apply_scip_data, _cleanup_funcref, and update resolve()**

Add these methods to the `ScipResolver` class in `archgraph/extractors/scip_resolver.py`:

```python
    def _match_target_node(
        self, file_path: str, line: int, name: str,
    ) -> Node | None:
        """Find the func: node matching a SCIP definition."""
        file_path = file_path.replace("\\", "/")
        funcs = self._func_ranges.get(file_path, [])
        # Exact line match first
        for start, end, node in funcs:
            if node.properties.get("name") == name and start == line + 1:
                # SCIP lines are 0-indexed, our nodes are 1-indexed
                return node
        # Fallback: name match in same file, closest line
        candidates = [
            (abs(start - (line + 1)), node)
            for start, end, node in funcs
            if node.properties.get("name") == name
        ]
        if candidates:
            candidates.sort(key=lambda t: t[0])
            return candidates[0][1]
        return None

    def _apply_scip_data(self, scip_data: bytes, scip_languages: set[str]) -> int:
        """Parse SCIP index and generate CALLS edges. Returns count of edges created."""
        sym_to_def, references = parse_scip_index(scip_data)

        created = 0
        seen_edges: set[tuple[str, str]] = set()

        for ref_file, ref_line, symbol in references:
            if symbol not in sym_to_def:
                continue

            def_file, def_line, def_name = sym_to_def[symbol]

            # Find caller (which function contains this reference?)
            caller = self._find_enclosing_function(ref_file, ref_line + 1)
            # +1 because SCIP is 0-indexed, our func ranges are 1-indexed
            if caller is None:
                continue

            # Find target node in graph
            target = self._match_target_node(def_file, def_line, def_name)
            if target is None:
                continue

            # Skip self-calls to same node
            if caller.id == target.id:
                continue

            # Deduplicate
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

        # Find all callers from SCIP-covered files
        scip_covered_files: set[str] = set()
        from archgraph.config import EXTENSION_MAP
        for node in self._graph.nodes:
            if node.label == NodeLabel.FILE:
                path = node.properties.get("path", "")
                ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
                lang = EXTENSION_MAP.get(ext.lower(), "")
                if lang in scip_languages:
                    scip_covered_files.add(path)

        # Build caller_id → file lookup
        node_file: dict[str, str] = {}
        for n in self._graph.nodes:
            if n.label == NodeLabel.FUNCTION:
                node_file[n.id] = n.properties.get("file", "").replace("\\", "/")

        norm_covered = {f.replace("\\", "/") for f in scip_covered_files}

        # Remove CALLS edges from SCIP-covered callers to funcref targets
        self._graph.edges = [
            e for e in self._graph.edges
            if not (
                e.type == EdgeType.CALLS
                and e.target_id.startswith("funcref:")
                and node_file.get(e.source_id, "") in norm_covered
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

        # Run SCIP indexers for covered languages
        for lang in self._languages:
            indexer_cls = INDEXER_REGISTRY.get(lang)
            if indexer_cls is None:
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
            # Add related languages (e.g., typescript indexer also covers javascript)
            if lang == "typescript":
                scip_languages.add("javascript")
            elif lang == "javascript":
                scip_languages.add("typescript")

        # Apply SCIP data
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scip_resolver.py::TestEdgeGeneration tests/test_scip_resolver.py::TestFuncrefCleanup -v`
Expected: PASS

- [ ] **Step 5: Run all SCIP tests**

Run: `pytest tests/test_scip_resolver.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add archgraph/extractors/scip_resolver.py tests/test_scip_resolver.py
git commit -m "feat: implement SCIP resolution with edge generation and funcref cleanup"
```

---

### Task 5: Pipeline Integration

**Files:**
- Modify: `archgraph/graph/builder.py`
- Test: `tests/test_scip_resolver.py`

- [ ] **Step 1: Write fallback test**

Append to `tests/test_scip_resolver.py`:

```python
class TestFallback:
    """Test that non-SCIP languages fall back to heuristic resolver."""

    def test_c_uses_heuristic(self):
        """C has no SCIP indexer — CallResolver should handle it."""
        graph = GraphData()
        graph.add_node("func:src/a.c:helper:1", NodeLabel.FUNCTION,
                        name="helper", file="src/a.c", line_start=1, line_end=3)
        graph.add_node("func:src/a.c:main:5", NodeLabel.FUNCTION,
                        name="main", file="src/a.c", line_start=5, line_end=10)
        graph.add_node("funcref:helper", NodeLabel.FUNCTION, name="helper")
        graph.add_edge("func:src/a.c:main:5", "funcref:helper", EdgeType.CALLS)

        resolver = ScipResolver(graph, Path("/fake"), ["c"])
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        # Heuristic should resolve intra-file call
        assert calls[0].target_id == "func:src/a.c:helper:1"
```

- [ ] **Step 2: Run test**

Run: `pytest tests/test_scip_resolver.py::TestFallback -v`
Expected: PASS (heuristic fallback already implemented in resolve())

- [ ] **Step 3: Update builder.py — replace CallResolver with ScipResolver**

In `archgraph/graph/builder.py`, add import at top:

```python
from archgraph.extractors.scip_resolver import ScipResolver
```

Replace the three `CallResolver(graph).resolve()` calls:

**Sequential pipeline (~line 294-296):**
```python
        # Step 4.5: Call resolution (SCIP + heuristic fallback)
        logger.info("Step 4.5/%d: Call resolution", total_steps)
        ScipResolver(graph, self.config.repo_path, self.config.languages).resolve()
```

**Parallel pipeline (~line 463-465):**
```python
            # Step 4.5: Call resolution (SCIP + heuristic fallback)
            logger.info("Step 4.5/%d: Call resolution", total_steps)
            ScipResolver(graph, self.config.repo_path, self.config.languages).resolve()
```

**Incremental pipeline (~line 160-162):**
```python
        # Step 4.5: Call resolution (SCIP + heuristic fallback)
        logger.info("Incremental call resolution")
        ScipResolver(graph, self.config.repo_path, self.config.languages).resolve()
```

- [ ] **Step 4: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add archgraph/graph/builder.py tests/test_scip_resolver.py
git commit -m "feat: integrate ScipResolver into extraction pipeline"
```

---

### Task 6: Real-World Validation

**Files:** None (manual test)

- [ ] **Step 1: Run extraction on claude-code-rev**

```bash
archgraph extract /c/Users/Deaxu/Desktop/claude-code-rev --clear-db --include-body
```

Expected: Log shows:
- `"Installing @sourcegraph/scip-typescript..."` (or already available)
- `"Running scip-typescript index..."`
- `"SCIP: created XXXX resolved CALLS edges for javascript, typescript"`
- Much higher resolution count than the previous 32,954

- [ ] **Step 2: Query Neo4j to compare**

```bash
archgraph query "MATCH ()-[c:CALLS {source: 'scip'}]->() RETURN count(c) AS scip_calls"
archgraph query "MATCH ()-[c:CALLS {resolved: true}]->() RETURN count(c) AS total_resolved"
archgraph query "MATCH (f:Function)-[c:CALLS {source: 'scip'}]->(t:Function) RETURN f.name AS caller, t.name AS target, t.file AS target_file LIMIT 10"
```

- [ ] **Step 3: Commit any fixes**

```bash
git add -A && git commit -m "fix: adjustments from real-world SCIP validation"
```

---

### Task 7: Documentation

**Files:**
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Update architecture docs**

Replace the existing "Call Resolution (Step 4.5)" section in `docs/ARCHITECTURE.md`:

```markdown
### Call Resolution (Step 4.5)

After all structural extraction is merged, call resolution runs in two stages:

**Stage 1 — SCIP (compiler-backed):** For languages with SCIP indexers (currently
TypeScript/JavaScript), the indexer is auto-installed and run. SCIP uses the
language's own compiler/type-checker to produce cross-reference data, achieving
~82% resolution accuracy. Old `funcref:` nodes for SCIP-covered languages are
removed and replaced with compiler-verified CALLS edges (`source: "scip"`).

**Stage 2 — Heuristic fallback:** For languages without SCIP support (C, C++, Rust,
Java, Go, etc.), the `CallResolver` runs its 4-level fallback chain:
qualifier match, intra-file, import-based, global unique (~43% accuracy).

SCIP indexers are installed automatically via the language's package manager.
Adding a new language requires implementing the `ScipIndexer` protocol
(install + index methods) and adding it to `INDEXER_REGISTRY`.

Supported SCIP indexers:
| Language | Indexer | Status |
|----------|---------|--------|
| TypeScript/JavaScript | `@sourcegraph/scip-typescript` | Active |
| Python | `scip-python` | TODO |
| Java/Kotlin | `scip-java` | TODO |
| Rust | `rust-analyzer` | TODO |
| Go | `scip-go` | TODO |
| C/C++ | `scip-clang` | TODO |
```

- [ ] **Step 2: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All pass.

- [ ] **Step 3: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs: update call resolution docs for SCIP integration"
```
