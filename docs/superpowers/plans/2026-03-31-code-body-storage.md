# Code Body Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store source code as `body` property on Function/Class/Struct/Interface/Enum nodes so AI agents can read code directly from the graph.

**Architecture:** Tree-sitter extractor already has access to AST nodes and source bytes during extraction. We add body text extraction to each `_extract_*` method, a class shell algorithm that replaces method bodies with `{ ... }`, and a `source` tool across all API surfaces (MCP, rlm-agent, core Python). Body is opt-out via `--no-body`.

**Tech Stack:** Python 3.11+, tree-sitter, Neo4j, Click CLI, MCP SDK

**Spec:** `docs/superpowers/specs/2026-03-31-code-body-storage-design.md`

---

## File Structure

| File | Role |
|------|------|
| `archgraph/config.py` | Add `include_body`, `max_body_size` to `ExtractConfig` |
| `archgraph/cli.py` | Add `--no-body`, `--max-body-size` CLI options |
| `archgraph/extractors/treesitter.py` | Body extraction in `_extract_*` methods + `_extract_class_shell()` + `_truncate_body()` |
| `archgraph/graph/neo4j_store.py` | `get_source()` convenience method |
| `archgraph/mcp/server.py` | `source` tool + body filtering in `context` |
| `archgraph/tool/archgraph_tool.py` | `source()` method + updated `_DESCRIPTION` |
| `tests/test_body_extraction.py` | All body-related tests |
| `docs/ARCHITECTURE.md` | Document body properties |

---

### Task 1: Config & CLI Foundation

**Files:**
- Modify: `archgraph/config.py:176-203` (`ExtractConfig` dataclass)
- Modify: `archgraph/cli.py:102-121` (extract command options)
- Modify: `archgraph/cli.py:122-181` (extract function signature + config construction)
- Test: `tests/test_body_extraction.py` (new file)

- [ ] **Step 1: Write failing test for config defaults**

Create `tests/test_body_extraction.py`:

```python
"""Tests for code body extraction feature."""

import textwrap
from pathlib import Path

import pytest

from archgraph.config import ExtractConfig


class TestBodyConfig:
    """Test include_body and max_body_size config fields."""

    def test_include_body_default_true(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"))
        assert config.include_body is True

    def test_max_body_size_default(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"))
        assert config.max_body_size == 51_200

    def test_include_body_override(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"), include_body=False)
        assert config.include_body is False

    def test_max_body_size_override(self):
        config = ExtractConfig(repo_path=Path("/tmp/test"), max_body_size=10_000)
        assert config.max_body_size == 10_000
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_body_extraction.py::TestBodyConfig -v`
Expected: FAIL — `ExtractConfig` does not have `include_body` or `max_body_size` fields.

- [ ] **Step 3: Add config fields**

In `archgraph/config.py`, add to the `ExtractConfig` dataclass (after `include_skills: bool = False` on line 202):

```python
    include_body: bool = True  # Store source code in graph nodes
    max_body_size: int = 51_200  # 50KB max per node, truncate beyond
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_body_extraction.py::TestBodyConfig -v`
Expected: All 4 tests PASS.

- [ ] **Step 5: Add CLI options**

In `archgraph/cli.py`, add two options after line 117 (`--include-process/--no-process`):

```python
@click.option("--include-body/--no-body", default=True, help="Store source code bodies in graph nodes")
@click.option("--max-body-size", type=int, default=51_200, help="Max body size in bytes (truncate beyond)")
```

Update the `extract` function signature (line 122) to add parameters:

```python
    include_body: bool,
    max_body_size: int,
```

Update the `ExtractConfig` construction (around line 163) to pass the new fields:

```python
        include_body=include_body,
        max_body_size=max_body_size,
```

- [ ] **Step 6: Run full test suite to verify nothing breaks**

Run: `pytest tests/ -v --tb=short`
Expected: Same pass/skip/fail counts as before (159 collected, 137 passed, 22 skipped).

- [ ] **Step 7: Commit**

```bash
git add archgraph/config.py archgraph/cli.py tests/test_body_extraction.py
git commit -m "feat: add include_body and max_body_size config fields"
```

---

### Task 2: Function Body Extraction

**Files:**
- Modify: `archgraph/extractors/treesitter.py:154-161` (`__init__` — accept body settings)
- Modify: `archgraph/extractors/treesitter.py:415-451` (`_extract_function` — add body)
- Modify: `archgraph/graph/builder.py:230,542` (pass body settings to extractor)
- Test: `tests/test_body_extraction.py`

- [ ] **Step 1: Write failing test for C function body**

Add to `tests/test_body_extraction.py`:

```python
from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import NodeLabel


@pytest.fixture
def tmp_c_with_functions(tmp_path):
    """C file with functions of varying complexity."""
    src = tmp_path / "main.c"
    src.write_text(textwrap.dedent("""\
        int add(int a, int b) {
            return a + b;
        }

        void empty_func(void) {
        }
    """))
    return tmp_path


class TestFunctionBody:
    """Test function body extraction."""

    def test_c_function_body(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=True)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "add":
                assert "body" in node.properties
                assert "int add(int a, int b)" in node.properties["body"]
                assert "return a + b;" in node.properties["body"]
                assert node.properties.get("body_lines", 0) > 0
                return
        pytest.fail("Function 'add' not found")

    def test_empty_function_body(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=True)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "empty_func":
                assert "body" in node.properties
                assert "void empty_func(void)" in node.properties["body"]
                assert node.properties.get("body_lines", 0) >= 1
                return
        pytest.fail("Function 'empty_func' not found")

    def test_no_body_when_disabled(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and not node.id.startswith("funcref:"):
                assert "body" not in node.properties
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_body_extraction.py::TestFunctionBody -v`
Expected: FAIL — `TreeSitterExtractor.__init__()` got unexpected keyword argument `include_body`.

- [ ] **Step 3: Implement body extraction in TreeSitterExtractor**

In `archgraph/extractors/treesitter.py`:

**3a.** Update `__init__` (line 157) to accept body settings:

```python
    def __init__(
        self,
        languages: list[str] | None = None,
        include_body: bool = True,
        max_body_size: int = 51_200,
    ) -> None:
        self._languages = languages or ["c", "cpp", "rust", "java", "go"]
        self._include_body = include_body
        self._max_body_size = max_body_size
        self._parsers: dict[str, ts.Parser] = {}
        self._ts_languages: dict[str, ts.Language] = {}
        self._thread_local = threading.local()
        self._init_parsers()
```

**3b.** Add `_truncate_body` helper method (after `_init_parsers`, around line 190):

```python
    def _truncate_body(self, text: str) -> tuple[str, bool]:
        """Truncate body if it exceeds max_body_size. Returns (text, was_truncated)."""
        encoded = text.encode("utf-8")
        if len(encoded) <= self._max_body_size:
            return text, False
        # Truncate at last newline within limit
        truncated = encoded[:self._max_body_size]
        last_nl = truncated.rfind(b"\n")
        if last_nl > 0:
            truncated = truncated[:last_nl]
        total_lines = text.count("\n") + 1
        decoded = truncated.decode("utf-8", errors="replace")
        decoded += f"\n// ... [truncated: {total_lines} total lines]"
        return decoded, True
```

**3c.** Update `_extract_function` (line 436-446) to add body properties. Replace the `graph.add_node(...)` call:

```python
        props: dict[str, Any] = dict(
            name=name,
            file=rel_path,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            params=params,
            return_type=return_type,
            is_exported=is_exported,
        )

        if self._include_body:
            body_text = _node_text(node, source)
            body_text, truncated = self._truncate_body(body_text)
            props["body"] = body_text
            props["body_lines"] = body_text.count("\n") + 1
            if truncated:
                props["body_truncated"] = True

        graph.add_node(func_id, NodeLabel.FUNCTION, **props)
```

Note: add `from typing import Any` import if not present (it is already imported at line 12).

**3d.** Update `GraphBuilder` to pass body settings to the extractor. In `archgraph/graph/builder.py`:

In `_build_sequential` (line 230):
```python
        ts_extractor = TreeSitterExtractor(
            languages=self.config.languages,
            include_body=self.config.include_body,
            max_body_size=self.config.max_body_size,
        )
```

In `_step_treesitter` (line 542):
```python
    def _step_treesitter(self, repo: Path, workers: int) -> GraphData:
        ts_extractor = TreeSitterExtractor(
            languages=self.config.languages,
            include_body=self.config.include_body,
            max_body_size=self.config.max_body_size,
        )
        return ts_extractor.extract(repo, workers=workers)
```

Also update the incremental path in `_run_incremental_steps` (line 131):
```python
            ts_ext = TreeSitterExtractor(
                languages=self.config.languages,
                include_body=self.config.include_body,
                max_body_size=self.config.max_body_size,
            )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_body_extraction.py::TestFunctionBody -v`
Expected: All 3 tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: Previous tests still pass. New body properties are added but no existing test checks for their absence.

- [ ] **Step 6: Commit**

```bash
git add archgraph/extractors/treesitter.py archgraph/graph/builder.py tests/test_body_extraction.py
git commit -m "feat: extract function body as node property"
```

---

### Task 3: Class Shell Extraction

**Files:**
- Modify: `archgraph/extractors/treesitter.py:453-482` (`_extract_class` — add shell body)
- Test: `tests/test_body_extraction.py`

- [ ] **Step 1: Write failing test for class shell**

Add to `tests/test_body_extraction.py`:

```python
@pytest.fixture
def tmp_java_project(tmp_path):
    """Java file with a class containing methods."""
    src = tmp_path / "App.java"
    src.write_text(textwrap.dedent("""\
        public class App {
            private int count;

            public App(int initial) {
                this.count = initial;
            }

            public int getCount() {
                return this.count;
            }

            public void increment() {
                this.count++;
            }
        }
    """))
    return tmp_path


class TestClassShell:
    """Test class shell extraction — method bodies replaced with { ... }."""

    def test_java_class_shell(self, tmp_java_project):
        ext = TreeSitterExtractor(languages=["java"], include_body=True)
        graph = ext.extract(tmp_java_project)

        for node in graph.nodes:
            if node.label == NodeLabel.CLASS and node.properties.get("name") == "App":
                body = node.properties.get("body", "")
                # Should contain class header and field
                assert "class App" in body
                assert "private int count" in body
                # Method signatures should be present
                assert "public App(int initial)" in body
                assert "public int getCount()" in body
                assert "public void increment()" in body
                # Method bodies should be replaced with ...
                assert "this.count = initial" not in body
                assert "return this.count" not in body
                assert "this.count++" not in body
                assert "..." in body
                return
        pytest.fail("Class 'App' not found")

    def test_class_no_body_when_disabled(self, tmp_java_project):
        ext = TreeSitterExtractor(languages=["java"], include_body=False)
        graph = ext.extract(tmp_java_project)

        for node in graph.nodes:
            if node.label == NodeLabel.CLASS:
                assert "body" not in node.properties
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_body_extraction.py::TestClassShell -v`
Expected: FAIL — Class nodes have no `body` property.

- [ ] **Step 3: Implement class shell extraction**

In `archgraph/extractors/treesitter.py`:

**3a.** Add `_iter_descendants` helper (near the other helpers, around line 140):

```python
def _iter_descendants(node: ts.Node) -> list[ts.Node]:
    """Iterate all descendant nodes."""
    result: list[ts.Node] = []
    for child in node.children:
        result.append(child)
        result.extend(_iter_descendants(child))
    return result
```

**3b.** Add `_body_compound_types` — the set of node types that represent function bodies across languages (add as module-level constant near `_LANG_NODE_TYPES`):

```python
_BODY_COMPOUND_TYPES = frozenset({
    "compound_statement", "block", "function_body",
    "statement_block", "class_body", "declaration_list",
})
```

**3c.** Add `_extract_class_shell` method to `TreeSitterExtractor` (after `_extract_class`):

```python
    def _extract_class_shell(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        lang_types: dict[str, list[str]],
    ) -> str:
        """Extract class source with method bodies replaced by { ... }."""
        class_bytes = bytearray(source[node.start_byte:node.end_byte])
        offset = node.start_byte

        func_types = lang_types.get("function_def", [])
        replacements: list[tuple[int, int]] = []

        for desc in _iter_descendants(node):
            if desc.type not in func_types:
                continue
            # Find the body node of this function
            body = desc.child_by_field_name("body")
            if body is None:
                for child in desc.children:
                    if child.type in _BODY_COMPOUND_TYPES:
                        body = child
                        break
            if body is None:
                continue
            # Replace content between { and } with ...
            inner_start = body.start_byte + 1 - offset
            inner_end = body.end_byte - 1 - offset
            if inner_start < inner_end:
                replacements.append((inner_start, inner_end))

        # Apply replacements in reverse order to preserve byte offsets
        for start, end in sorted(replacements, reverse=True):
            class_bytes[start:end] = b" ... "

        return class_bytes.decode("utf-8", errors="replace")
```

**3d.** Update `_extract_class` to use the shell. In the existing method (line 453-482), add body extraction before the `return cls_id`:

```python
        if self._include_body:
            lang_types = _LANG_NODE_TYPES.get(lang, {})
            shell = self._extract_class_shell(node, source, lang, lang_types)
            shell, truncated = self._truncate_body(shell)
            graph.nodes[-1].properties["body"] = shell
            graph.nodes[-1].properties["body_lines"] = shell.count("\n") + 1
            if truncated:
                graph.nodes[-1].properties["body_truncated"] = True
```

Note: we access `graph.nodes[-1]` because `add_node` just appended the class node. Alternatively, find the node by id — but since we just created it, `-1` is safe and simpler.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_body_extraction.py::TestClassShell -v`
Expected: Both tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: No regressions.

- [ ] **Step 6: Commit**

```bash
git add archgraph/extractors/treesitter.py tests/test_body_extraction.py
git commit -m "feat: extract class shell with method bodies replaced"
```

---

### Task 4: Struct, Interface, Enum Body Extraction

**Files:**
- Modify: `archgraph/extractors/treesitter.py:484-544` (`_extract_struct`, `_extract_interface`, `_extract_enum`)
- Test: `tests/test_body_extraction.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_body_extraction.py`:

```python
@pytest.fixture
def tmp_rust_with_types(tmp_path):
    """Rust file with struct, trait, and enum."""
    src = tmp_path / "types.rs"
    src.write_text(textwrap.dedent("""\
        pub struct Point {
            pub x: f64,
            pub y: f64,
        }

        pub trait Drawable {
            fn draw(&self);
            fn area(&self) -> f64;
        }

        pub enum Shape {
            Circle(f64),
            Rectangle(f64, f64),
        }
    """))
    return tmp_path


class TestStructInterfaceEnumBody:
    """Test body extraction for Struct, Interface, Enum nodes."""

    def test_rust_struct_body(self, tmp_rust_with_types):
        ext = TreeSitterExtractor(languages=["rust"], include_body=True)
        graph = ext.extract(tmp_rust_with_types)

        for node in graph.nodes:
            if node.label == NodeLabel.STRUCT and node.properties.get("name") == "Point":
                body = node.properties.get("body", "")
                assert "pub struct Point" in body
                assert "pub x: f64" in body
                assert "pub y: f64" in body
                return
        pytest.fail("Struct 'Point' not found")

    def test_rust_trait_body(self, tmp_rust_with_types):
        ext = TreeSitterExtractor(languages=["rust"], include_body=True)
        graph = ext.extract(tmp_rust_with_types)

        for node in graph.nodes:
            if node.label == NodeLabel.INTERFACE and node.properties.get("name") == "Drawable":
                body = node.properties.get("body", "")
                assert "trait Drawable" in body
                assert "fn draw" in body
                assert "fn area" in body
                return
        pytest.fail("Interface 'Drawable' not found")

    def test_rust_enum_body(self, tmp_rust_with_types):
        ext = TreeSitterExtractor(languages=["rust"], include_body=True)
        graph = ext.extract(tmp_rust_with_types)

        for node in graph.nodes:
            if node.label == NodeLabel.ENUM and node.properties.get("name") == "Shape":
                body = node.properties.get("body", "")
                assert "enum Shape" in body
                assert "Circle" in body
                assert "Rectangle" in body
                return
        pytest.fail("Enum 'Shape' not found")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_body_extraction.py::TestStructInterfaceEnumBody -v`
Expected: FAIL — nodes have no `body` property.

- [ ] **Step 3: Add body to struct, interface, enum extractors**

In `archgraph/extractors/treesitter.py`:

**3a.** Update `_extract_struct` (line 484-504). After `graph.add_node(...)`:

```python
        if self._include_body:
            body_text = _node_text(node, source)
            body_text, truncated = self._truncate_body(body_text)
            graph.nodes[-1].properties["body"] = body_text
            graph.nodes[-1].properties["body_lines"] = body_text.count("\n") + 1
            if truncated:
                graph.nodes[-1].properties["body_truncated"] = True
```

**3b.** Update `_extract_interface` (line 526-544). After `graph.add_node(...)`:

```python
        if self._include_body:
            body_text = _node_text(node, source)
            body_text, truncated = self._truncate_body(body_text)
            graph.nodes[-1].properties["body"] = body_text
            graph.nodes[-1].properties["body_lines"] = body_text.count("\n") + 1
            if truncated:
                graph.nodes[-1].properties["body_truncated"] = True
```

**3c.** Update `_extract_enum` (line 506-524). After `graph.add_node(...)`:

```python
        if self._include_body:
            body_text = _node_text(node, source)
            body_text, truncated = self._truncate_body(body_text)
            graph.nodes[-1].properties["body"] = body_text
            graph.nodes[-1].properties["body_lines"] = body_text.count("\n") + 1
            if truncated:
                graph.nodes[-1].properties["body_truncated"] = True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_body_extraction.py::TestStructInterfaceEnumBody -v`
Expected: All 3 tests PASS.

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: No regressions.

- [ ] **Step 6: Commit**

```bash
git add archgraph/extractors/treesitter.py tests/test_body_extraction.py
git commit -m "feat: extract body for struct, interface, and enum nodes"
```

---

### Task 5: Truncation Test

**Files:**
- Test: `tests/test_body_extraction.py`

- [ ] **Step 1: Write truncation test**

Add to `tests/test_body_extraction.py`:

```python
class TestBodyTruncation:
    """Test body truncation when exceeding max_body_size."""

    def test_truncation_with_small_limit(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=True, max_body_size=30)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "add":
                body = node.properties.get("body", "")
                assert node.properties.get("body_truncated") is True
                assert "truncated:" in body
                assert len(body.encode("utf-8")) < 200  # truncated + marker
                return
        pytest.fail("Function 'add' not found")

    def test_no_truncation_within_limit(self, tmp_c_with_functions):
        ext = TreeSitterExtractor(languages=["c"], include_body=True, max_body_size=51_200)
        graph = ext.extract(tmp_c_with_functions)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "add":
                assert node.properties.get("body_truncated") is None
                return
        pytest.fail("Function 'add' not found")
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_body_extraction.py::TestBodyTruncation -v`
Expected: Both PASS (implementation already done in Task 2).

- [ ] **Step 3: Commit**

```bash
git add tests/test_body_extraction.py
git commit -m "test: add body truncation edge case tests"
```

---

### Task 6: Neo4jStore.get_source() Method

**Files:**
- Modify: `archgraph/graph/neo4j_store.py:372-376` (after `query` method)
- Test: `tests/test_body_extraction.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_body_extraction.py`:

```python
from unittest.mock import MagicMock

from archgraph.graph.neo4j_store import Neo4jStore


class TestNeo4jGetSource:
    """Test Neo4jStore.get_source() with mocked driver."""

    def _make_store(self) -> Neo4jStore:
        store = Neo4jStore(uri="bolt://mock:7687")
        store._driver = MagicMock()
        return store

    def test_get_source_found(self):
        store = self._make_store()

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.__iter__ = MagicMock(return_value=iter([
            MagicMock(data=lambda: {
                "id": "func:main.c:add:1",
                "name": "add",
                "file": "main.c",
                "body": "int add(int a, int b) { return a + b; }",
                "body_lines": 1,
                "body_truncated": None,
            })
        ]))
        mock_session.run.return_value = mock_result
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        store._driver.session.return_value = mock_session

        result = store.get_source("func:main.c:add:1")
        assert result is not None
        assert result["body"] == "int add(int a, int b) { return a + b; }"

    def test_get_source_not_found(self):
        store = self._make_store()

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.__iter__ = MagicMock(return_value=iter([]))
        mock_session.run.return_value = mock_result
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        store._driver.session.return_value = mock_session

        result = store.get_source("func:nonexistent:0")
        assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_body_extraction.py::TestNeo4jGetSource -v`
Expected: FAIL — `Neo4jStore` has no `get_source` method.

- [ ] **Step 3: Implement get_source**

In `archgraph/graph/neo4j_store.py`, add after the `query` method (after line 376):

```python
    def get_source(self, symbol_id: str) -> dict[str, Any] | None:
        """Get source code for a symbol by its node ID.

        Returns dict with body, name, file, line_start, line_end, body_lines,
        body_truncated — or None if the symbol is not found or has no body.
        """
        results = self.query(
            "MATCH (n:_Node {_id: $id}) "
            "WHERE n.body IS NOT NULL "
            "RETURN n._id AS id, n.name AS name, n.file AS file, "
            "n.body AS body, n.body_lines AS body_lines, "
            "n.body_truncated AS body_truncated, "
            "n.line_start AS line_start, n.line_end AS line_end",
            {"id": symbol_id},
        )
        return results[0] if results else None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_body_extraction.py::TestNeo4jGetSource -v`
Expected: Both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add archgraph/graph/neo4j_store.py tests/test_body_extraction.py
git commit -m "feat: add Neo4jStore.get_source() method"
```

---

### Task 7: MCP Source Tool & Body Filtering

**Files:**
- Modify: `archgraph/mcp/server.py:16-126` (TOOLS list — add source tool)
- Modify: `archgraph/mcp/server.py:211-256` (handle_tool_call — add source handler)
- Modify: `archgraph/mcp/server.py:286-343` (_get_context — filter body)
- Test: `tests/test_body_extraction.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_body_extraction.py`:

```python
import asyncio


class TestMCPSourceTool:
    """Test MCP source tool and body filtering."""

    def test_source_tool_in_tools_list(self):
        from archgraph.mcp.server import TOOLS
        tool_names = [t["name"] for t in TOOLS]
        assert "source" in tool_names

    def test_source_tool_schema(self):
        from archgraph.mcp.server import TOOLS
        source_tool = next(t for t in TOOLS if t["name"] == "source")
        assert "symbol_id" in source_tool["inputSchema"]["properties"]
        assert "symbol_id" in source_tool["inputSchema"]["required"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_body_extraction.py::TestMCPSourceTool -v`
Expected: FAIL — `source` not in TOOLS list.

- [ ] **Step 3: Add source tool to MCP server**

**3a.** In `archgraph/mcp/server.py`, add to the `TOOLS` list (after the `stats` tool entry, before line 126):

```python
    {
        "name": "source",
        "description": "Get source code of a function, class, struct, or other symbol",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol_id": {
                    "type": "string",
                    "description": "Symbol node ID (e.g. 'func:src/auth.c:validate:42')",
                },
            },
            "required": ["symbol_id"],
        },
    },
```

**3b.** Add handler in `handle_tool_call` (in the if/elif chain, after the `stats` handler):

```python
            elif name == "source":
                symbol_id = arguments["symbol_id"]
                source_result = self._store.get_source(symbol_id)
                if source_result:
                    result = source_result
                else:
                    result = {"error": f"Symbol not found or has no body: {symbol_id}"}
```

**3c.** Update `_get_context` to filter body out of props (line 298):

Replace:
```python
        props = symbol[0].get("props", {})
```

With:
```python
        props = symbol[0].get("props", {})
        props.pop("body", None)  # body is served via the source tool
```

**3d.** Add `body_coverage` to `_get_stats` (in the return dict):

```python
        body_count = self._store.query(
            "MATCH (n:_Node) WHERE n.body IS NOT NULL RETURN count(n) AS count"
        )
        total_count = self._store.query(
            "MATCH (n:_Node) WHERE n.name IS NOT NULL RETURN count(n) AS count"
        )
        body_total = body_count[0]["count"] if body_count else 0
        named_total = total_count[0]["count"] if total_count else 1

        return {
            "graph_stats": db_stats,
            "clusters": cluster_count[0]["count"] if cluster_count else 0,
            "processes": process_count[0]["count"] if process_count else 0,
            "body_coverage": round(body_total / named_total * 100, 1) if named_total else 0,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_body_extraction.py::TestMCPSourceTool -v`
Expected: Both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add archgraph/mcp/server.py tests/test_body_extraction.py
git commit -m "feat: add MCP source tool and filter body from context"
```

---

### Task 8: rlm-agent Tool Update

**Files:**
- Modify: `archgraph/tool/archgraph_tool.py:36-37` (`_DESCRIPTION` — add body properties)
- Modify: `archgraph/tool/archgraph_tool.py:163-184` (add `source` method)
- Test: `tests/test_body_extraction.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_body_extraction.py`:

```python
class TestArchGraphToolSource:
    """Test rlm-agent tool source method."""

    def test_source_method_exists(self):
        from archgraph.tool.archgraph_tool import ArchGraphTool
        tool = ArchGraphTool.__new__(ArchGraphTool)
        assert hasattr(tool, "source")
        assert callable(tool.source)

    def test_description_mentions_body(self):
        from archgraph.tool.archgraph_tool import _DESCRIPTION
        assert "body" in _DESCRIPTION
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_body_extraction.py::TestArchGraphToolSource -v`
Expected: FAIL — no `source` method, no `body` in description.

- [ ] **Step 3: Update ArchGraphTool**

**3a.** Update `_DESCRIPTION` in `archgraph/tool/archgraph_tool.py`. In the Function line (line 36-37), add body properties:

Replace:
```python
- **Function**: name, file, line_start, is_exported, is_input_source, is_dangerous_sink, \
is_allocator, is_crypto, is_parser, is_unsafe, has_unsafe_block, has_transmute, \
has_force_unwrap, has_goroutine, has_channel_op, has_defer
```

With:
```python
- **Function**: name, file, line_start, line_end, body, body_lines, body_truncated, \
is_exported, is_input_source, is_dangerous_sink, is_allocator, is_crypto, is_parser, \
is_unsafe, has_unsafe_block, has_transmute, has_force_unwrap, has_goroutine, \
has_channel_op, has_defer
- **Class**: name, file, line_start, line_end, body (shell — method bodies replaced with ...)
- **Struct**: name, file, line_start, body
```

Also update the existing Class and Struct lines to include body.

**3b.** Add `source` method after the `query` method (after line 163):

```python
    @tool_method(
        description="Get source code of a symbol by its node ID",
        returns="dict with body, name, file, line range — or error",
    )
    def source(self, symbol_id: str) -> dict[str, Any]:
        """Get source code of a function, class, struct, or other symbol.

        Args:
            symbol_id: Node ID (e.g. "func:src/auth.c:validate:42").

        Returns:
            Dict with body, name, file, line_start, line_end, body_lines.
        """
        self._ensure_connected()
        result = self._store.get_source(symbol_id)
        if result is None:
            return {"error": f"Symbol not found or has no body: {symbol_id}"}
        return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_body_extraction.py::TestArchGraphToolSource -v`
Expected: Both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add archgraph/tool/archgraph_tool.py tests/test_body_extraction.py
git commit -m "feat: add source method to rlm-agent tool"
```

---

### Task 9: Documentation Update

**Files:**
- Modify: `docs/ARCHITECTURE.md:115-137` (Node Types table)
- Modify: `CLAUDE.md` (if needed)

- [ ] **Step 1: Update ARCHITECTURE.md node types table**

In `docs/ARCHITECTURE.md`, update the Node Types table. Add `body, body_lines, body_truncated` to key properties:

For the **Function** row, update Key Properties to:
```
name, file, line_start, line_end, params, return_type, body, body_lines, body_truncated, is_exported, is_input_source, is_dangerous_sink, is_allocator, is_crypto, is_parser, is_unsafe
```

For the **Class** row:
```
name, file, line_start, line_end, body (shell), body_lines, is_abstract
```

For the **Struct** row:
```
name, file, line_start, body, body_lines
```

For the **Interface** row:
```
name, file, line_start, body, body_lines
```

For the **Enum** row:
```
name, file, body, body_lines
```

- [ ] **Step 2: Add body section to ARCHITECTURE.md**

Add a new section after "### Neo4j Conventions" (around line 186):

```markdown
### Code Body Storage

Nodes carry their source code as a `body` property (enabled by default, opt-out via `--no-body`):

- **Function**: Full source text including signature and body
- **Class**: Shell — fields and method signatures preserved, method bodies replaced with `{ ... }`
- **Struct/Interface/Enum**: Full source text
- **Macro**: Already stores `body` (unchanged)

Properties:
- `body` (string): Source code text
- `body_lines` (int): Line count
- `body_truncated` (bool): True if truncated at `max_body_size` (default 50KB)

Access via the `source` tool (MCP/rlm-agent) or Cypher: `MATCH (f:Function {_id: $id}) RETURN f.body`
```

- [ ] **Step 3: Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs: document code body storage in architecture guide"
```

---

### Task 10: Multi-Language Body Test

**Files:**
- Test: `tests/test_body_extraction.py`

- [ ] **Step 1: Write cross-language body test**

Add to `tests/test_body_extraction.py`:

```python
@pytest.fixture
def tmp_go_project(tmp_path):
    """Go file with a function."""
    src = tmp_path / "main.go"
    src.write_text(textwrap.dedent("""\
        package main

        func add(a int, b int) int {
            return a + b
        }
    """))
    return tmp_path


@pytest.fixture
def tmp_ts_project(tmp_path):
    """TypeScript file with a function and class."""
    src = tmp_path / "app.ts"
    src.write_text(textwrap.dedent("""\
        export function greet(name: string): string {
            return `Hello, ${name}!`;
        }

        export class Counter {
            private count: number = 0;

            increment(): void {
                this.count++;
            }

            getCount(): number {
                return this.count;
            }
        }
    """))
    return tmp_path


class TestMultiLanguageBody:
    """Test body extraction across multiple languages."""

    def test_go_function_body(self, tmp_go_project):
        ext = TreeSitterExtractor(languages=["go"], include_body=True)
        graph = ext.extract(tmp_go_project)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "add":
                body = node.properties.get("body", "")
                assert "func add(a int, b int) int" in body
                assert "return a + b" in body
                return
        pytest.fail("Go function 'add' not found")

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"),
        reason="tree-sitter-typescript not installed",
    )
    def test_ts_function_body(self, tmp_ts_project):
        ext = TreeSitterExtractor(languages=["typescript"], include_body=True)
        graph = ext.extract(tmp_ts_project)

        for node in graph.nodes:
            if node.label == NodeLabel.FUNCTION and node.properties.get("name") == "greet":
                body = node.properties.get("body", "")
                assert "function greet" in body
                assert "return" in body
                return
        pytest.fail("TS function 'greet' not found")

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"),
        reason="tree-sitter-typescript not installed",
    )
    def test_ts_class_shell(self, tmp_ts_project):
        ext = TreeSitterExtractor(languages=["typescript"], include_body=True)
        graph = ext.extract(tmp_ts_project)

        for node in graph.nodes:
            if node.label == NodeLabel.CLASS and node.properties.get("name") == "Counter":
                body = node.properties.get("body", "")
                assert "class Counter" in body
                # Method signatures should be visible
                assert "increment()" in body
                assert "getCount()" in body
                # Method bodies should be replaced
                assert "this.count++" not in body
                return
        pytest.fail("TS class 'Counter' not found")
```

Also add the helper at module level:

```python
def _ts_lang_available(lang: str) -> bool:
    """Check if a tree-sitter language grammar is installed."""
    try:
        ext = TreeSitterExtractor(languages=[lang])
        return lang in ext._parsers
    except Exception:
        return False
```

- [ ] **Step 2: Run the tests**

Run: `pytest tests/test_body_extraction.py::TestMultiLanguageBody -v`
Expected: Go test PASS, TS tests PASS (or skip if grammar not installed).

- [ ] **Step 3: Run full test suite one final time**

Run: `pytest tests/ -v --tb=short`
Expected: All previous tests pass + all new body tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_body_extraction.py
git commit -m "test: add multi-language body extraction tests"
```
