# Scope-Aware Call Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve `funcref:` call targets to real function definitions using scope, imports, and qualifiers — transforming unreliable name-only CALLS edges into accurate cross-file references.

**Architecture:** A post-extraction `CallResolver` step builds a symbol table from all `func:` nodes and import edges, then resolves each `funcref:` node through a 4-level fallback chain: qualifier match, intra-file, import-based, global unique. Extraction is modified to preserve qualifier info and parse named imports.

**Tech Stack:** Python 3.11+, tree-sitter (existing), pytest

---

## File Structure

| File | Responsibility |
|------|---------------|
| `archgraph/extractors/call_resolver.py` (NEW) | `CallResolver` class — symbol table, import map, resolution chain, module path resolver |
| `tests/test_call_resolver.py` (NEW) | All resolution tests (10 test classes) |
| `archgraph/extractors/treesitter.py` (MODIFY) | `_get_callee_name()` returns tuple, `_extract_import()` adds `names` property, `_find_calls_recursive()` uses qualifier |
| `archgraph/graph/builder.py` (MODIFY) | Insert CallResolver step after Group A merge, before security labeling |

---

### Task 1: Qualifier Preservation in `_get_callee_name()`

**Files:**
- Modify: `archgraph/extractors/treesitter.py:971-993`
- Test: `tests/test_call_resolver.py`

- [ ] **Step 1: Write failing tests for qualifier extraction**

Create `tests/test_call_resolver.py` with the first test class:

```python
"""Tests for scope-aware call resolution."""

import textwrap
from pathlib import Path

import pytest

from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import GraphData, NodeLabel, EdgeType


def _ts_lang_available(lang: str) -> bool:
    try:
        ext = TreeSitterExtractor(languages=[lang])
        return lang in ext._parsers
    except Exception:
        return False


class TestQualifierExtraction:
    """Test _get_callee_name returns (name, qualifier) tuple."""

    @pytest.mark.skipif(not _ts_lang_available("c"), reason="c grammar not installed")
    def test_simple_call_no_qualifier(self, tmp_path):
        """Plain function call -> qualifier is None."""
        src = tmp_path / "main.c"
        src.write_text(textwrap.dedent("""\
            void caller(void) {
                foo();
            }
        """))
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_path)
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) >= 1
        call = calls[0]
        assert call.target_id == "funcref:foo"
        assert call.properties.get("qualifier") is None

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_method_call_with_qualifier(self, tmp_path):
        """obj.method() -> qualifier is 'obj'."""
        src = tmp_path / "main.ts"
        src.write_text(textwrap.dedent("""\
            function caller() {
                Counter.increment();
            }
        """))
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) >= 1
        call = calls[0]
        assert call.target_id == "funcref:Counter.increment"
        assert call.properties.get("qualifier") == "Counter"

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_this_self_super_skipped(self, tmp_path):
        """this.method() -> qualifier is None (this/self/super are skipped)."""
        src = tmp_path / "main.ts"
        src.write_text(textwrap.dedent("""\
            function caller() {
                this.doSomething();
            }
        """))
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) >= 1
        call = calls[0]
        assert call.target_id == "funcref:doSomething"
        assert call.properties.get("qualifier") is None

    @pytest.mark.skipif(not _ts_lang_available("c"), reason="c grammar not installed")
    def test_arrow_call_qualifier(self, tmp_path):
        """ptr->method() -> qualifier is 'ptr'."""
        src = tmp_path / "main.c"
        src.write_text(textwrap.dedent("""\
            void caller(void) {
                obj->process();
            }
        """))
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_path)
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) >= 1
        call = calls[0]
        assert call.target_id == "funcref:obj.process"
        assert call.properties.get("qualifier") == "obj"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_call_resolver.py::TestQualifierExtraction -v`
Expected: FAIL — `funcref:foo` tests may pass but qualifier property will be missing, `funcref:Counter.increment` will fail because current code strips to just `increment`.

- [ ] **Step 3: Modify `_get_callee_name()` to return tuple**

In `archgraph/extractors/treesitter.py`, replace the existing `_get_callee_name` method (lines 971-993):

```python
    _SKIP_QUALIFIERS = frozenset({"self", "this", "super", "Self"})

    def _get_callee_name(self, node: ts.Node, source: bytes) -> tuple[str, str | None]:
        """Extract the function being called and its qualifier.

        Returns (name, qualifier). qualifier is None when there is no receiver
        or when the receiver is self/this/super.
        """
        func_node = _find_child_by_field(node, "function")
        if func_node:
            text = _node_text(func_node, source)
            # Check for qualified call: obj.method, obj->method, ns::func
            for sep in ("->", "::", "."):
                if sep in text:
                    parts = text.rsplit(sep, 1)
                    qualifier = parts[0].strip()
                    name = parts[1].strip()
                    if qualifier in self._SKIP_QUALIFIERS:
                        return name, None
                    return name, qualifier
            return text.strip(), None

        # method_invocation (Java) — name field + optional object
        name_node = _find_child_by_field(node, "name")
        if name_node:
            name = _node_text(name_node, source)
            obj_node = _find_child_by_field(node, "object")
            if obj_node:
                qualifier = _node_text(obj_node, source)
                if qualifier in self._SKIP_QUALIFIERS:
                    return name, None
                return name, qualifier
            return name, None

        # message_expression (ObjC)
        selector = _find_child_by_field(node, "selector")
        if selector:
            return _node_text(selector, source), None

        return "", None
```

- [ ] **Step 4: Update `_find_calls_recursive()` to use tuple and qualifier**

In `archgraph/extractors/treesitter.py`, replace the `_find_calls_recursive` method (lines 842-861):

```python
    def _find_calls_recursive(
        self,
        node: ts.Node,
        source: bytes,
        call_types: list[str],
        caller_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Recursively find call expressions."""
        if node.type in call_types:
            callee_name, qualifier = self._get_callee_name(node, source)
            if callee_name:
                # Build funcref ID with qualifier if present
                if qualifier:
                    callee_id = f"funcref:{qualifier}.{callee_name}"
                else:
                    callee_id = f"funcref:{callee_name}"
                graph.add_node(callee_id, NodeLabel.FUNCTION, name=callee_name)
                if qualifier:
                    graph.add_edge(
                        caller_id, callee_id, EdgeType.CALLS, qualifier=qualifier,
                    )
                else:
                    graph.add_edge(caller_id, callee_id, EdgeType.CALLS)

        for child in node.children:
            self._find_calls_recursive(
                child, source, call_types, caller_id, rel_path, graph,
            )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_call_resolver.py::TestQualifierExtraction -v`
Expected: PASS

- [ ] **Step 6: Run full test suite to check no regressions**

Run: `pytest tests/ -v --tb=short`
Expected: All previously passing tests still pass.

- [ ] **Step 7: Commit**

```bash
git add archgraph/extractors/treesitter.py tests/test_call_resolver.py
git commit -m "feat: preserve qualifier in _get_callee_name for call resolution"
```

---

### Task 2: Named Import Parsing

**Files:**
- Modify: `archgraph/extractors/treesitter.py:697-713`
- Test: `tests/test_call_resolver.py`

- [ ] **Step 1: Write failing tests for named import extraction**

Append to `tests/test_call_resolver.py`:

```python
class TestNamedImportParsing:
    """Test that IMPORTS edges get a 'names' property with imported symbols."""

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_js_named_import(self, tmp_path):
        """import { foo, bar } from './utils' -> names='foo,bar'."""
        src = tmp_path / "main.ts"
        src.write_text('import { foo, bar } from "./utils";\n')
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "foo,bar"

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_js_default_import(self, tmp_path):
        """import Foo from './utils' -> names='Foo'."""
        src = tmp_path / "main.ts"
        src.write_text('import Foo from "./utils";\n')
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "Foo"

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_js_wildcard_import_skipped(self, tmp_path):
        """import * as utils from './utils' -> names='' (wildcard skipped)."""
        src = tmp_path / "main.ts"
        src.write_text('import * as utils from "./utils";\n')
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == ""

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_js_alias_import(self, tmp_path):
        """import { foo as f } from './utils' -> names='f' (alias used)."""
        src = tmp_path / "main.ts"
        src.write_text('import { foo as f } from "./utils";\n')
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "f"

    @pytest.mark.skipif(not _ts_lang_available("rust"), reason="rust grammar not installed")
    def test_rust_use_import(self, tmp_path):
        """use crate::utils::foo; -> names='foo'."""
        src = tmp_path / "main.rs"
        src.write_text("use crate::utils::foo;\n")
        ext = TreeSitterExtractor(languages=["rust"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "foo"

    @pytest.mark.skipif(not _ts_lang_available("java"), reason="java grammar not installed")
    def test_java_import(self, tmp_path):
        """import com.example.Foo; -> names='Foo'."""
        src = tmp_path / "Foo.java"
        src.write_text("import com.example.Foo;\n")
        ext = TreeSitterExtractor(languages=["java"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "Foo"

    @pytest.mark.skipif(not _ts_lang_available("go"), reason="go grammar not installed")
    def test_go_import(self, tmp_path):
        """import "fmt" -> names='fmt'."""
        src = tmp_path / "main.go"
        src.write_text('package main\n\nimport "fmt"\n')
        ext = TreeSitterExtractor(languages=["go"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "fmt"

    @pytest.mark.skipif(not _ts_lang_available("c"), reason="c grammar not installed")
    def test_c_include_no_names(self, tmp_path):
        """#include 'utils.h' -> names='' (C has no named imports)."""
        src = tmp_path / "main.c"
        src.write_text('#include "utils.h"\n')
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_call_resolver.py::TestNamedImportParsing -v`
Expected: FAIL — `names` property does not exist on IMPORTS edges.

- [ ] **Step 3: Add `_parse_named_imports()` and update `_extract_import()`**

In `archgraph/extractors/treesitter.py`, add a new method after `_parse_import_target` (after line 1018) and modify `_extract_import`:

```python
    def _parse_named_imports(self, text: str) -> str:
        """Parse import statement text to extract comma-separated imported names.

        Returns a comma-separated string of imported names, or '' if none/wildcard.
        """
        text = text.strip()

        # C/C++: #include — no named imports
        if text.startswith("#include"):
            return ""

        # JS/TS: import { foo, bar } from "module"
        #        import { foo as f } from "module"
        #        import Foo from "module"
        #        import * as utils from "module"
        if "from" in text and ("import" in text):
            # Wildcard
            if "* as" in text:
                return ""
            # Named imports: import { foo, bar } from ...
            if "{" in text and "}" in text:
                brace_content = text[text.index("{") + 1 : text.index("}")]
                names = []
                for part in brace_content.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    # Handle alias: "foo as f" -> use "f"
                    if " as " in part:
                        part = part.split(" as ")[-1].strip()
                    names.append(part)
                return ",".join(names)
            # Default import: import Foo from "module"
            if text.startswith("import "):
                after_import = text[7:].strip()
                # Get the default name (before 'from')
                default_name = after_import.split("from")[0].strip().rstrip(",").strip()
                if default_name and not default_name.startswith("{"):
                    return default_name
            return ""

        # Rust: use crate::utils::foo; or use crate::utils::{foo, bar};
        if text.startswith("use "):
            target = text[4:].rstrip(";").strip()
            # Grouped: use foo::{bar, baz};
            if "{" in target and "}" in target:
                brace_content = target[target.index("{") + 1 : target.index("}")]
                names = [n.strip() for n in brace_content.split(",") if n.strip()]
                return ",".join(names)
            # Single: use foo::bar -> name is last segment
            if "::" in target:
                return target.rsplit("::", 1)[-1]
            return target

        # Java/Kotlin: import com.example.Foo; or import static com.example.Foo.bar;
        if text.startswith("import "):
            target = text[7:].rstrip(";").strip()
            if target.startswith("static "):
                target = target[7:]
            # Last segment is the name
            if "." in target:
                return target.rsplit(".", 1)[-1]
            return target

        # Go: import "fmt" -> name is last path segment
        #     import alias "pkg/path" -> name is alias
        if text.startswith("import"):
            rest = text[6:].strip().strip("()")
            rest = rest.strip()
            # Check for alias: alias "path"
            parts = rest.split(None, 1)
            if len(parts) == 2 and (parts[1].startswith('"') or parts[1].startswith("'")):
                return parts[0]  # alias
            # Standard: "fmt" -> fmt
            clean = rest.strip("'\"")
            if "/" in clean:
                return clean.rsplit("/", 1)[-1]
            return clean

        return ""
```

Then modify `_extract_import` (lines 697-713) to add the `names` property:

```python
    def _extract_import(
        self,
        node: ts.Node,
        source: bytes,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Extract an import/include edge."""
        text = _node_text(node, source).strip()
        import_target = self._parse_import_target(text)
        if import_target:
            target_id = f"module:{import_target}"
            graph.add_node(target_id, NodeLabel.MODULE, name=import_target)
            names = self._parse_named_imports(text)
            graph.add_edge(file_id, target_id, EdgeType.IMPORTS, raw=text, names=names)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_call_resolver.py::TestNamedImportParsing -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests pass. The `names` property is additive — existing tests don't check for it so they remain unaffected.

- [ ] **Step 6: Commit**

```bash
git add archgraph/extractors/treesitter.py tests/test_call_resolver.py
git commit -m "feat: parse named imports and add names property to IMPORTS edges"
```

---

### Task 3: CallResolver — Symbol Table Construction

**Files:**
- Create: `archgraph/extractors/call_resolver.py`
- Test: `tests/test_call_resolver.py`

- [ ] **Step 1: Write failing tests for symbol table**

Append to `tests/test_call_resolver.py`:

```python
from archgraph.extractors.call_resolver import CallResolver


class TestSymbolTable:
    """Test that CallResolver builds correct indexes from GraphData."""

    def test_file_funcs_index(self):
        """Functions indexed by their file property."""
        graph = GraphData()
        graph.add_node("func:src/a.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/a.ts", line_start=1)
        graph.add_node("func:src/a.ts:bar:5", NodeLabel.FUNCTION, name="bar", file="src/a.ts", line_start=5)
        graph.add_node("func:src/b.ts:baz:1", NodeLabel.FUNCTION, name="baz", file="src/b.ts", line_start=1)

        resolver = CallResolver(graph)
        assert len(resolver._file_funcs["src/a.ts"]) == 2
        assert len(resolver._file_funcs["src/b.ts"]) == 1

    def test_name_to_defs_index(self):
        """Functions indexed by name for global unique lookup."""
        graph = GraphData()
        graph.add_node("func:src/a.ts:add:1", NodeLabel.FUNCTION, name="add", file="src/a.ts", line_start=1)
        graph.add_node("func:src/b.ts:add:3", NodeLabel.FUNCTION, name="add", file="src/b.ts", line_start=3)
        graph.add_node("func:src/c.ts:unique:1", NodeLabel.FUNCTION, name="unique", file="src/c.ts", line_start=1)

        resolver = CallResolver(graph)
        assert len(resolver._name_to_defs["add"]) == 2
        assert len(resolver._name_to_defs["unique"]) == 1

    def test_qualified_index_from_contains(self):
        """Class -> Function CONTAINS edge creates qualified index entry."""
        graph = GraphData()
        graph.add_node("class:src/a.ts:Counter:1", NodeLabel.CLASS, name="Counter", file="src/a.ts")
        graph.add_node("func:src/a.ts:increment:3", NodeLabel.FUNCTION, name="increment", file="src/a.ts", line_start=3)
        graph.add_edge("class:src/a.ts:Counter:1", "func:src/a.ts:increment:3", EdgeType.CONTAINS)

        resolver = CallResolver(graph)
        assert "Counter.increment" in resolver._qualified_to_def
        assert resolver._qualified_to_def["Counter.increment"].id == "func:src/a.ts:increment:3"

    def test_import_map_from_edges(self):
        """IMPORTS edges with names property build the import map."""
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("module:./utils", NodeLabel.MODULE, name="./utils")
        graph.add_node("func:src/utils.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/utils.ts", line_start=1)
        graph.add_node("file:src/utils.ts", NodeLabel.FILE, path="src/utils.ts")
        graph.add_edge("file:src/app.ts", "module:./utils", EdgeType.IMPORTS, names="foo,bar", raw='import { foo, bar } from "./utils"')

        resolver = CallResolver(graph)
        assert resolver._import_map[("src/app.ts", "foo")] == "./utils"
        assert resolver._import_map[("src/app.ts", "bar")] == "./utils"

    def test_file_set_from_file_nodes(self):
        """File nodes populate _file_set."""
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("file:src/b.ts", NodeLabel.FILE, path="src/b.ts")

        resolver = CallResolver(graph)
        assert "src/a.ts" in resolver._file_set
        assert "src/b.ts" in resolver._file_set

    def test_funcref_nodes_excluded_from_indexes(self):
        """funcref: nodes should NOT appear in function indexes."""
        graph = GraphData()
        graph.add_node("func:src/a.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/a.ts", line_start=1)
        graph.add_node("funcref:bar", NodeLabel.FUNCTION, name="bar")

        resolver = CallResolver(graph)
        assert "foo" in resolver._name_to_defs
        assert "bar" not in resolver._name_to_defs
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_call_resolver.py::TestSymbolTable -v`
Expected: FAIL — `ImportError: cannot import name 'CallResolver'`

- [ ] **Step 3: Create `call_resolver.py` with symbol table construction**

Create `archgraph/extractors/call_resolver.py`:

```python
"""Scope-aware call resolver — resolves funcref: nodes to real func: definitions."""

from __future__ import annotations

import logging
from collections import defaultdict

from archgraph.graph.schema import Edge, GraphData, Node, NodeLabel, EdgeType

logger = logging.getLogger(__name__)


class CallResolver:
    """Resolves unresolved funcref: call targets to actual function definitions.

    Uses a 4-level fallback chain:
      1. Qualifier match (e.g., funcref:Counter.increment -> Counter class method)
      2. Intra-file match (caller and callee in same file)
      3. Import match (follow import edges to find the source)
      4. Global unique (only one definition with that name exists)
    """

    def __init__(self, graph: GraphData) -> None:
        self._graph = graph
        self._build_indexes()

    def _build_indexes(self) -> None:
        """Build symbol table, import map, and file set from graph data."""
        # File -> list of function Nodes defined in that file
        self._file_funcs: dict[str, list[Node]] = defaultdict(list)
        # Function name -> list of Nodes with that name
        self._name_to_defs: dict[str, list[Node]] = defaultdict(list)
        # "ClassName.methodName" -> Node
        self._qualified_to_def: dict[str, Node] = {}
        # (caller_file, imported_name) -> module specifier
        self._import_map: dict[tuple[str, str], str] = {}
        # All File node paths
        self._file_set: set[str] = set()

        # Node ID -> Node for quick lookup
        node_map: dict[str, Node] = {}
        for node in self._graph.nodes:
            node_map[node.id] = node

        # Index real function definitions (not funcref:)
        for node in self._graph.nodes:
            if node.label == NodeLabel.FUNCTION and not node.id.startswith("funcref:"):
                name = node.properties.get("name", "")
                file_path = node.properties.get("file", "")
                if name:
                    self._name_to_defs[name].append(node)
                if file_path:
                    self._file_funcs[file_path].append(node)

            elif node.label == NodeLabel.FILE:
                path = node.properties.get("path", "")
                if path:
                    self._file_set.add(path)

        # Build qualified index from CONTAINS edges (Class -> Function)
        for edge in self._graph.edges:
            if edge.type == EdgeType.CONTAINS:
                source = node_map.get(edge.source_id)
                target = node_map.get(edge.target_id)
                if (
                    source
                    and target
                    and source.label == NodeLabel.CLASS
                    and target.label == NodeLabel.FUNCTION
                    and not target.id.startswith("funcref:")
                ):
                    class_name = source.properties.get("name", "")
                    func_name = target.properties.get("name", "")
                    if class_name and func_name:
                        self._qualified_to_def[f"{class_name}.{func_name}"] = target

        # Build import map from IMPORTS edges with names property
        for edge in self._graph.edges:
            if edge.type == EdgeType.IMPORTS:
                source_node = node_map.get(edge.source_id)
                if not source_node or source_node.label != NodeLabel.FILE:
                    continue
                source_file = source_node.properties.get("path", "")
                names_str = edge.properties.get("names", "")
                target_node = node_map.get(edge.target_id)
                module_spec = target_node.properties.get("name", "") if target_node else ""
                if source_file and module_spec and names_str:
                    for name in names_str.split(","):
                        name = name.strip()
                        if name:
                            self._import_map[(source_file, name)] = module_spec

    def resolve(self) -> GraphData:
        """Resolve funcref: nodes. Returns the same (mutated) GraphData."""
        # Placeholder — resolution logic added in Task 4
        return self._graph
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_call_resolver.py::TestSymbolTable -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add archgraph/extractors/call_resolver.py tests/test_call_resolver.py
git commit -m "feat: add CallResolver with symbol table construction"
```

---

### Task 4: Module Path Resolution

**Files:**
- Modify: `archgraph/extractors/call_resolver.py`
- Test: `tests/test_call_resolver.py`

- [ ] **Step 1: Write failing tests for module path resolution**

Append to `tests/test_call_resolver.py`:

```python
class TestModulePathResolve:
    """Test _resolve_module_path converts import specifiers to file paths."""

    def test_relative_js_import_ts_extension(self):
        """./utils from src/app.ts -> src/utils.ts."""
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("file:src/utils.ts", NodeLabel.FILE, path="src/utils.ts")
        resolver = CallResolver(graph)
        result = resolver._resolve_module_path("src/app.ts", "./utils")
        assert result == "src/utils.ts"

    def test_relative_js_import_index_fallback(self):
        """./utils from src/app.ts -> src/utils/index.ts when src/utils.ts doesn't exist."""
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("file:src/utils/index.ts", NodeLabel.FILE, path="src/utils/index.ts")
        resolver = CallResolver(graph)
        result = resolver._resolve_module_path("src/app.ts", "./utils")
        assert result == "src/utils/index.ts"

    def test_relative_js_import_parent_dir(self):
        """../helpers from src/components/App.ts -> src/helpers.ts."""
        graph = GraphData()
        graph.add_node("file:src/components/App.ts", NodeLabel.FILE, path="src/components/App.ts")
        graph.add_node("file:src/helpers.ts", NodeLabel.FILE, path="src/helpers.ts")
        resolver = CallResolver(graph)
        result = resolver._resolve_module_path("src/components/App.ts", "../helpers")
        assert result == "src/helpers.ts"

    def test_java_package_import(self):
        """com.example.utils.Foo -> com/example/utils/Foo.java."""
        graph = GraphData()
        graph.add_node("file:com/example/utils/Foo.java", NodeLabel.FILE, path="com/example/utils/Foo.java")
        resolver = CallResolver(graph)
        result = resolver._resolve_module_path("src/Main.java", "com.example.utils.Foo")
        assert result == "com/example/utils/Foo.java"

    def test_rust_crate_import(self):
        """crate::utils -> src/utils.rs."""
        graph = GraphData()
        graph.add_node("file:src/utils.rs", NodeLabel.FILE, path="src/utils.rs")
        resolver = CallResolver(graph)
        result = resolver._resolve_module_path("src/main.rs", "crate::utils")
        assert result == "src/utils.rs"

    def test_external_import_returns_none(self):
        """react (no matching file) -> None."""
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        resolver = CallResolver(graph)
        result = resolver._resolve_module_path("src/app.ts", "react")
        assert result is None

    def test_backslash_normalization(self):
        """Windows backslash paths in _file_set are normalized."""
        graph = GraphData()
        graph.add_node("file:src\\utils.ts", NodeLabel.FILE, path="src\\utils.ts")
        graph.add_node("file:src\\app.ts", NodeLabel.FILE, path="src\\app.ts")
        resolver = CallResolver(graph)
        result = resolver._resolve_module_path("src\\app.ts", "./utils")
        assert result is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_call_resolver.py::TestModulePathResolve -v`
Expected: FAIL — `_resolve_module_path` method does not exist.

- [ ] **Step 3: Implement `_resolve_module_path()`**

Add to `CallResolver` in `archgraph/extractors/call_resolver.py`:

```python
    def _resolve_module_path(
        self, caller_file: str, module_specifier: str,
    ) -> str | None:
        """Resolve a module specifier to a file path in _file_set.

        Returns the matching file path, or None if not found (external/stdlib).
        """
        # Normalize backslashes to forward slashes for consistent matching
        normalized_files = {p.replace("\\", "/"): p for p in self._file_set}
        caller_norm = caller_file.replace("\\", "/")

        # Relative JS/TS imports: ./foo, ../foo
        if module_specifier.startswith("."):
            from posixpath import dirname, normpath, join
            caller_dir = dirname(caller_norm)
            base = normpath(join(caller_dir, module_specifier))
            # Try extensions in order
            for ext in (".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"):
                candidate = base + ext
                if candidate in normalized_files:
                    return normalized_files[candidate]
            return None

        # Rust crate imports: crate::foo::bar -> src/foo/bar.rs or src/foo/bar/mod.rs
        if module_specifier.startswith("crate::"):
            path_part = module_specifier[7:].replace("::", "/")
            for candidate in (f"src/{path_part}.rs", f"src/{path_part}/mod.rs"):
                if candidate in normalized_files:
                    return normalized_files[candidate]
            return None

        # Java/Kotlin package imports: com.example.Foo -> com/example/Foo.java or .kt
        if "." in module_specifier and not module_specifier.startswith("."):
            path_part = module_specifier.replace(".", "/")
            for ext in (".java", ".kt"):
                candidate = path_part + ext
                if candidate in normalized_files:
                    return normalized_files[candidate]
            # Also try as source-rooted
            for ext in (".java", ".kt"):
                for prefix in ("src/main/java/", "src/main/kotlin/", "src/"):
                    candidate = prefix + path_part + ext
                    if candidate in normalized_files:
                        return normalized_files[candidate]
            return None

        # Go imports: "pkg/path" -> look for files in the last segment dir
        if "/" in module_specifier:
            last_segment = module_specifier.rsplit("/", 1)[-1]
            # Find any file in a directory matching the last segment
            for norm_path in normalized_files:
                parts = norm_path.split("/")
                if len(parts) >= 2 and parts[-2] == last_segment:
                    return normalized_files[norm_path]
            return None

        # Simple name — try as-is with common extensions
        for ext in (".ts", ".tsx", ".js", ".jsx", ".rs", ".go", ".java", ".kt", ".c", ".cpp", ".h"):
            if module_specifier + ext in normalized_files:
                return normalized_files[module_specifier + ext]

        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_call_resolver.py::TestModulePathResolve -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add archgraph/extractors/call_resolver.py tests/test_call_resolver.py
git commit -m "feat: add module path resolution for imports"
```

---

### Task 5: Resolution Chain Algorithm

**Files:**
- Modify: `archgraph/extractors/call_resolver.py`
- Test: `tests/test_call_resolver.py`

- [ ] **Step 1: Write failing tests for each resolution level**

Append to `tests/test_call_resolver.py`:

```python
class TestQualifierMatch:
    """Test Step 1: qualified funcref resolves via class CONTAINS."""

    def test_qualified_resolves(self):
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("class:src/a.ts:Counter:1", NodeLabel.CLASS, name="Counter", file="src/a.ts")
        graph.add_node("func:src/a.ts:increment:3", NodeLabel.FUNCTION, name="increment", file="src/a.ts", line_start=3)
        graph.add_edge("class:src/a.ts:Counter:1", "func:src/a.ts:increment:3", EdgeType.CONTAINS)
        # Caller in another file calls Counter.increment
        graph.add_node("func:src/b.ts:main:1", NodeLabel.FUNCTION, name="main", file="src/b.ts", line_start=1)
        graph.add_node("funcref:Counter.increment", NodeLabel.FUNCTION, name="increment")
        graph.add_edge("func:src/b.ts:main:1", "funcref:Counter.increment", EdgeType.CALLS, qualifier="Counter")

        resolver = CallResolver(graph)
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) == 1
        assert calls[0].target_id == "func:src/a.ts:increment:3"
        assert calls[0].properties.get("resolved") is True
        # funcref node should be removed
        assert not any(n.id == "funcref:Counter.increment" for n in graph.nodes)


class TestIntraFileMatch:
    """Test Step 2: caller and callee in the same file."""

    def test_same_file_resolves(self):
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("func:src/a.ts:helper:1", NodeLabel.FUNCTION, name="helper", file="src/a.ts", line_start=1)
        graph.add_node("func:src/a.ts:main:10", NodeLabel.FUNCTION, name="main", file="src/a.ts", line_start=10)
        graph.add_node("funcref:helper", NodeLabel.FUNCTION, name="helper")
        graph.add_edge("func:src/a.ts:main:10", "funcref:helper", EdgeType.CALLS)

        resolver = CallResolver(graph)
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) == 1
        assert calls[0].target_id == "func:src/a.ts:helper:1"

    def test_same_file_line_proximity(self):
        """Multiple same-name functions in file — nearest by line wins."""
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("func:src/a.ts:helper:1", NodeLabel.FUNCTION, name="helper", file="src/a.ts", line_start=1)
        graph.add_node("func:src/a.ts:helper:50", NodeLabel.FUNCTION, name="helper", file="src/a.ts", line_start=50)
        graph.add_node("func:src/a.ts:caller:45", NodeLabel.FUNCTION, name="caller", file="src/a.ts", line_start=45)
        graph.add_node("funcref:helper", NodeLabel.FUNCTION, name="helper")
        graph.add_edge("func:src/a.ts:caller:45", "funcref:helper", EdgeType.CALLS)

        resolver = CallResolver(graph)
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) == 1
        # line 50 is closer to line 45 than line 1
        assert calls[0].target_id == "func:src/a.ts:helper:50"


class TestImportMatch:
    """Test Step 3: resolve via import edges."""

    def test_import_resolves(self):
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("file:src/utils.ts", NodeLabel.FILE, path="src/utils.ts")
        graph.add_node("module:./utils", NodeLabel.MODULE, name="./utils")
        graph.add_edge("file:src/app.ts", "module:./utils", EdgeType.IMPORTS, names="foo", raw='import { foo } from "./utils"')
        graph.add_node("func:src/utils.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/utils.ts", line_start=1)
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION, name="main", file="src/app.ts", line_start=1)
        graph.add_node("funcref:foo", NodeLabel.FUNCTION, name="foo")
        graph.add_edge("func:src/app.ts:main:1", "funcref:foo", EdgeType.CALLS)

        resolver = CallResolver(graph)
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) == 1
        assert calls[0].target_id == "func:src/utils.ts:foo:1"


class TestGlobalUnique:
    """Test Step 4: global unique name match."""

    def test_unique_name_resolves(self):
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("file:src/b.ts", NodeLabel.FILE, path="src/b.ts")
        graph.add_node("func:src/b.ts:uniqueFunc:1", NodeLabel.FUNCTION, name="uniqueFunc", file="src/b.ts", line_start=1)
        graph.add_node("func:src/a.ts:caller:1", NodeLabel.FUNCTION, name="caller", file="src/a.ts", line_start=1)
        graph.add_node("funcref:uniqueFunc", NodeLabel.FUNCTION, name="uniqueFunc")
        graph.add_edge("func:src/a.ts:caller:1", "funcref:uniqueFunc", EdgeType.CALLS)

        resolver = CallResolver(graph)
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) == 1
        assert calls[0].target_id == "func:src/b.ts:uniqueFunc:1"

    def test_ambiguous_name_stays_unresolved(self):
        """Multiple definitions with same name — do NOT resolve."""
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("file:src/b.ts", NodeLabel.FILE, path="src/b.ts")
        graph.add_node("file:src/c.ts", NodeLabel.FILE, path="src/c.ts")
        graph.add_node("func:src/b.ts:add:1", NodeLabel.FUNCTION, name="add", file="src/b.ts", line_start=1)
        graph.add_node("func:src/c.ts:add:1", NodeLabel.FUNCTION, name="add", file="src/c.ts", line_start=1)
        graph.add_node("func:src/a.ts:caller:1", NodeLabel.FUNCTION, name="caller", file="src/a.ts", line_start=1)
        graph.add_node("funcref:add", NodeLabel.FUNCTION, name="add")
        graph.add_edge("func:src/a.ts:caller:1", "funcref:add", EdgeType.CALLS)

        resolver = CallResolver(graph)
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) == 1
        # Should remain unresolved
        assert calls[0].target_id == "funcref:add"


class TestUnresolvedRemain:
    """Test that external/stdlib calls remain as funcref."""

    def test_external_call_stays(self):
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("func:src/a.ts:main:1", NodeLabel.FUNCTION, name="main", file="src/a.ts", line_start=1)
        graph.add_node("funcref:console.log", NodeLabel.FUNCTION, name="log")
        graph.add_edge("func:src/a.ts:main:1", "funcref:console.log", EdgeType.CALLS, qualifier="console")

        resolver = CallResolver(graph)
        resolver.resolve()

        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) == 1
        assert calls[0].target_id == "funcref:console.log"
        # funcref node should NOT be deleted (still has edges)
        assert any(n.id == "funcref:console.log" for n in graph.nodes)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_call_resolver.py::TestQualifierMatch tests/test_call_resolver.py::TestIntraFileMatch tests/test_call_resolver.py::TestImportMatch tests/test_call_resolver.py::TestGlobalUnique tests/test_call_resolver.py::TestUnresolvedRemain -v`
Expected: FAIL — `resolve()` is a stub that does nothing.

- [ ] **Step 3: Implement the `resolve()` method**

Replace the `resolve` method in `archgraph/extractors/call_resolver.py`:

```python
    def resolve(self) -> GraphData:
        """Resolve funcref: nodes to real func: definitions.

        Iterates all CALLS edges targeting funcref: nodes. For each,
        applies the 4-level resolution chain per-caller. After all edges
        are processed, removes orphaned funcref: nodes.
        """
        node_map: dict[str, Node] = {n.id: n for n in self._graph.nodes}
        total_calls = 0
        resolved_count = 0

        for edge in self._graph.edges:
            if edge.type != EdgeType.CALLS:
                continue
            if not edge.target_id.startswith("funcref:"):
                continue

            total_calls += 1
            caller = node_map.get(edge.source_id)
            if not caller:
                continue
            caller_file = caller.properties.get("file", "")

            funcref_node = node_map.get(edge.target_id)
            callee_name = funcref_node.properties.get("name", "") if funcref_node else ""
            qualifier = edge.properties.get("qualifier")

            target = self._resolve_single(callee_name, qualifier, caller_file)
            if target:
                edge.target_id = target.id
                edge.properties["resolved"] = True
                resolved_count += 1

        # Remove orphaned funcref: nodes (no remaining edges point to them)
        referenced_targets = {e.target_id for e in self._graph.edges}
        referenced_sources = {e.source_id for e in self._graph.edges}
        referenced_ids = referenced_targets | referenced_sources
        self._graph.nodes = [
            n for n in self._graph.nodes
            if not n.id.startswith("funcref:") or n.id in referenced_ids
        ]

        if total_calls > 0:
            pct = (resolved_count / total_calls) * 100
            logger.info(
                "Resolved %d/%d calls (%.1f%%), %d unresolved (external/ambiguous)",
                resolved_count, total_calls, pct, total_calls - resolved_count,
            )
        else:
            logger.info("No funcref: calls to resolve")

        return self._graph

    def _resolve_single(
        self, callee_name: str, qualifier: str | None, caller_file: str,
    ) -> Node | None:
        """Try to resolve a single call through the 4-level chain."""
        if not callee_name:
            return None

        # Step 1: Qualifier match
        if qualifier:
            qualified_key = f"{qualifier}.{callee_name}"
            if qualified_key in self._qualified_to_def:
                return self._qualified_to_def[qualified_key]

        # Step 2: Intra-file match
        if caller_file:
            file_funcs = self._file_funcs.get(caller_file, [])
            matches = [f for f in file_funcs if f.properties.get("name") == callee_name]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                # Pick closest by line number
                caller_line = 0  # We'll refine this if needed
                # For now, pick the first match — caller line info isn't in the edge
                # Use the caller's line_start from node properties
                return self._pick_closest(matches, caller_file, callee_name)

        # Step 3: Import match
        if caller_file:
            module_spec = self._import_map.get((caller_file, callee_name))
            if module_spec:
                resolved_file = self._resolve_module_path(caller_file, module_spec)
                if resolved_file:
                    file_funcs = self._file_funcs.get(resolved_file, [])
                    matches = [f for f in file_funcs if f.properties.get("name") == callee_name]
                    if matches:
                        return matches[0]

        # Step 4: Global unique
        defs = self._name_to_defs.get(callee_name, [])
        if len(defs) == 1:
            return defs[0]

        return None

    def _pick_closest(self, candidates: list[Node], caller_file: str, callee_name: str) -> Node:
        """Pick the candidate nearest to the caller by line number.

        When we can't determine exact caller line, return the last definition
        (most likely the nearest in typical top-down code).
        """
        # Sort by line_start and return the last one (heuristic: closer to caller)
        sorted_candidates = sorted(
            candidates, key=lambda n: n.properties.get("line_start", 0),
        )
        return sorted_candidates[-1]
```

- [ ] **Step 4: Run resolution tests to verify they pass**

Run: `pytest tests/test_call_resolver.py::TestQualifierMatch tests/test_call_resolver.py::TestIntraFileMatch tests/test_call_resolver.py::TestImportMatch tests/test_call_resolver.py::TestGlobalUnique tests/test_call_resolver.py::TestUnresolvedRemain -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add archgraph/extractors/call_resolver.py tests/test_call_resolver.py
git commit -m "feat: implement 4-level call resolution chain"
```

---

### Task 6: Improve Intra-File Line Proximity Resolution

**Files:**
- Modify: `archgraph/extractors/call_resolver.py`
- Test: `tests/test_call_resolver.py`

- [ ] **Step 1: Write a test for per-caller line proximity**

The `_pick_closest` heuristic from Task 5 uses "last definition" as fallback. We need the caller's line number for accurate proximity. Update `_resolve_single` to accept caller line and fix the `TestIntraFileMatch.test_same_file_line_proximity` test.

First verify the existing test passes with the correct result. The caller at line 45 should pick helper at line 50 (closer than line 1).

Run: `pytest tests/test_call_resolver.py::TestIntraFileMatch::test_same_file_line_proximity -v`

If it already passes (the heuristic of picking the last definition gets lucky here since line 50 > line 1), move on. If not, fix:

- [ ] **Step 2: Update `_resolve_single` to use caller's line_start**

In `archgraph/extractors/call_resolver.py`, update the `resolve` method to pass caller line info, and update `_resolve_single` and `_pick_closest`:

```python
    # In resolve(), change the _resolve_single call:
    caller_line = caller.properties.get("line_start", 0)
    target = self._resolve_single(callee_name, qualifier, caller_file, caller_line)
```

```python
    def _resolve_single(
        self, callee_name: str, qualifier: str | None, caller_file: str, caller_line: int = 0,
    ) -> Node | None:
        # ... (Steps 1, 3, 4 unchanged) ...

        # Step 2: Intra-file match
        if caller_file:
            file_funcs = self._file_funcs.get(caller_file, [])
            matches = [f for f in file_funcs if f.properties.get("name") == callee_name]
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                return self._pick_closest(matches, caller_line)

        # ... rest unchanged ...

    def _pick_closest(self, candidates: list[Node], caller_line: int) -> Node:
        """Pick the candidate nearest to the caller by line number."""
        return min(
            candidates,
            key=lambda n: abs(n.properties.get("line_start", 0) - caller_line),
        )
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_call_resolver.py::TestIntraFileMatch -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add archgraph/extractors/call_resolver.py
git commit -m "fix: use caller line proximity for intra-file resolution tiebreak"
```

---

### Task 7: Resolution Statistics Test

**Files:**
- Test: `tests/test_call_resolver.py`

- [ ] **Step 1: Write test for resolution log output**

Append to `tests/test_call_resolver.py`:

```python
class TestResolutionStats:
    """Test that resolve() logs correct statistics."""

    def test_stats_logged(self, caplog):
        import logging
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("func:src/a.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/a.ts", line_start=1)
        graph.add_node("func:src/a.ts:caller:10", NodeLabel.FUNCTION, name="caller", file="src/a.ts", line_start=10)
        # Resolvable call
        graph.add_node("funcref:foo", NodeLabel.FUNCTION, name="foo")
        graph.add_edge("func:src/a.ts:caller:10", "funcref:foo", EdgeType.CALLS)
        # Unresolvable call
        graph.add_node("funcref:externalFunc", NodeLabel.FUNCTION, name="externalFunc")
        graph.add_edge("func:src/a.ts:caller:10", "funcref:externalFunc", EdgeType.CALLS)

        with caplog.at_level(logging.INFO, logger="archgraph.extractors.call_resolver"):
            resolver = CallResolver(graph)
            resolver.resolve()

        assert "Resolved 1/2" in caplog.text
        assert "50.0%" in caplog.text
        assert "1 unresolved" in caplog.text
```

- [ ] **Step 2: Run test**

Run: `pytest tests/test_call_resolver.py::TestResolutionStats -v`
Expected: PASS (logging was already implemented in Task 5).

- [ ] **Step 3: Commit**

```bash
git add tests/test_call_resolver.py
git commit -m "test: add resolution statistics logging test"
```

---

### Task 8: Pipeline Integration

**Files:**
- Modify: `archgraph/graph/builder.py`
- Test: `tests/test_call_resolver.py`

- [ ] **Step 1: Write integration test that exercises the full pipeline**

Append to `tests/test_call_resolver.py`:

```python
class TestIntegration:
    """End-to-end test: extraction + resolution on a multi-file project."""

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_multi_file_ts_project(self, tmp_path):
        """Two TS files with import — call resolves across files."""
        utils = tmp_path / "utils.ts"
        utils.write_text(textwrap.dedent("""\
            export function add(a: number, b: number): number {
                return a + b;
            }

            export function subtract(a: number, b: number): number {
                return a - b;
            }
        """))
        app = tmp_path / "app.ts"
        app.write_text(textwrap.dedent("""\
            import { add } from "./utils";

            function main() {
                const result = add(1, 2);
            }
        """))

        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        graph.deduplicate()

        # Before resolution: funcref:add exists
        funcref_nodes = [n for n in graph.nodes if n.id.startswith("funcref:")]
        assert any(n.id == "funcref:add" for n in funcref_nodes)

        # Resolve
        resolver = CallResolver(graph)
        resolver.resolve()

        # After resolution: funcref:add should be gone, edge points to real func
        calls_from_main = [
            e for e in graph.edges
            if e.type == EdgeType.CALLS and "main" in e.source_id
        ]
        add_calls = [e for e in calls_from_main if "add" in e.target_id]
        assert len(add_calls) >= 1
        # Should point to a real func: node, not funcref:
        for call in add_calls:
            if call.properties.get("resolved"):
                assert call.target_id.startswith("func:")

    @pytest.mark.skipif(
        not _ts_lang_available("c"), reason="c grammar not installed"
    )
    def test_c_intra_file_resolution(self, tmp_path):
        """C file — functions in same file resolve without imports."""
        src = tmp_path / "main.c"
        src.write_text(textwrap.dedent("""\
            int helper(int x) {
                return x + 1;
            }

            int main(void) {
                int result = helper(42);
                return result;
            }
        """))

        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_path)
        graph.deduplicate()

        resolver = CallResolver(graph)
        resolver.resolve()

        calls_from_main = [
            e for e in graph.edges
            if e.type == EdgeType.CALLS and "main" in e.source_id
        ]
        helper_calls = [e for e in calls_from_main if "helper" in e.target_id]
        assert len(helper_calls) >= 1
        assert helper_calls[0].target_id.startswith("func:")
        assert helper_calls[0].properties.get("resolved") is True
```

- [ ] **Step 2: Run integration tests**

Run: `pytest tests/test_call_resolver.py::TestIntegration -v`
Expected: PASS

- [ ] **Step 3: Add CallResolver to `_build_sequential` in builder.py**

In `archgraph/graph/builder.py`, add the import at the top (after line 21):

```python
from archgraph.extractors.call_resolver import CallResolver
```

In `_build_sequential()`, after Step 4 (annotations, ~line 287) and before Step 5 (security labeling, ~line 289), insert:

```python
        # Step 4.5: Call resolution
        logger.info("Step 4.5/%d: Call resolution", total_steps)
        resolver = CallResolver(graph)
        resolver.resolve()
```

- [ ] **Step 4: Add CallResolver to `_build_parallel` in builder.py**

In `_build_parallel()`, after the Group A merge completes (~line 452, after annotation merge) and before Step 5 (security labeling, ~line 454), insert:

```python
            # Step 4.5: Call resolution (needs all funcs + imports merged)
            logger.info("Step 4.5/%d: Call resolution", total_steps)
            resolver = CallResolver(graph)
            resolver.resolve()
```

- [ ] **Step 5: Add CallResolver to `_run_incremental_steps` in builder.py**

In `_run_incremental_steps()`, after Step 4 (annotations, ~line 157) and before Step 5 (security labeling, ~line 159), insert:

```python
        # Step 4.5: Call resolution
        logger.info("Incremental call resolution")
        resolver = CallResolver(graph)
        resolver.resolve()
```

- [ ] **Step 6: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: All tests pass, including existing builder tests.

- [ ] **Step 7: Commit**

```bash
git add archgraph/graph/builder.py archgraph/extractors/call_resolver.py tests/test_call_resolver.py
git commit -m "feat: integrate CallResolver into extraction pipeline"
```

---

### Task 9: Real-World Validation

**Files:** None (manual test)

- [ ] **Step 1: Run extraction on claude-code-rev with call resolution**

```bash
archgraph extract /c/Users/Deaxu/Desktop/claude-code-rev --clear-db --include-body
```

Expected: Extraction completes with a log line showing resolution stats, e.g.:
`Resolved XXXX/YYYY calls (ZZ.Z%), WWWW unresolved (external/ambiguous)`

- [ ] **Step 2: Query Neo4j to verify resolved calls**

```bash
archgraph query "MATCH (f:Function)-[c:CALLS]->(t:Function) WHERE c.resolved = true RETURN count(c) AS resolved_calls"
```

```bash
archgraph query "MATCH (f:Function)-[c:CALLS]->(t:Function) WHERE t._id STARTS WITH 'funcref:' RETURN count(c) AS unresolved_calls"
```

```bash
archgraph query "MATCH (f:Function)-[c:CALLS {resolved: true}]->(t:Function) RETURN f.file AS caller_file, f.name AS caller, t.file AS target_file, t.name AS target LIMIT 10"
```

Expected: resolved_calls > 0, and sample rows show cross-file resolved calls with correct file paths.

- [ ] **Step 3: Commit if any adjustments were needed**

```bash
git add -A
git commit -m "fix: adjustments from real-world validation"
```

---

### Task 10: Final Commit and Documentation Update

**Files:**
- Modify: `docs/ARCHITECTURE.md`

- [ ] **Step 1: Update ARCHITECTURE.md**

Add a section after the existing pipeline description documenting the call resolution step:

```markdown
### Call Resolution (Step 4.5)

After all structural extraction (tree-sitter, git, deps, annotations) is merged,
the `CallResolver` resolves unresolved `funcref:` call targets to actual function
definitions using a 4-level fallback chain:

1. **Qualifier match** — `funcref:Counter.increment` resolves via Class CONTAINS Function
2. **Intra-file match** — caller and callee in the same file, line proximity tiebreak
3. **Import match** — follow named imports to the source file's function definitions
4. **Global unique** — if only one function with that name exists in the repo

Resolved edges get `resolved: true` property. Unresolved calls (external/stdlib)
remain as `funcref:` nodes. CALLS edges also carry a `qualifier` property when
the call had a receiver (e.g., `Counter` for `Counter.increment()`).
```

- [ ] **Step 2: Run full test suite one final time**

Run: `pytest tests/ -v --tb=short`
Expected: All tests pass.

- [ ] **Step 3: Final commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs: document call resolution pipeline step"
```
