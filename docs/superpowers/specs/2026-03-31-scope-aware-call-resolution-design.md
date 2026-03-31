# Scope-Aware Call Resolution — Design Spec

**Date:** 2026-03-31
**Status:** Approved

## Problem

ArchGraph currently creates all CALLS edges as unresolved `funcref:{name}` references.
No attempt is made to match call targets to actual function definitions in the codebase.
This means every downstream analysis (impact, taint, clustering) operates on unreliable edges.

Example: `funcref:add` exists but never links to `func:src/math.ts:add:5` — even when
the caller imports and directly calls that exact function.

## Goals

1. Resolve `funcref:` nodes to real `func:` definitions using scope, imports, and qualifiers
2. Preserve unresolved references for external/stdlib calls (no data loss)
3. Operate as a post-extraction pipeline step (no changes to parallel extraction)
4. Support all 10 languages tree-sitter handles

## Non-Goals

- Full type inference or overload resolution
- Wildcard import expansion (`import *`)
- Runtime/dynamic dispatch resolution
- Cross-repo dependency resolution

---

## Architecture

### New Module

`archgraph/extractors/call_resolver.py` — single class `CallResolver`.

Takes `GraphData`, mutates it in-place by resolving funcref nodes, returns same `GraphData`.

### Pipeline Position

After Group A (tree-sitter, git, deps, annotations) merge, before security labeling:

```
Group A (concurrent):  Step 1 (tree-sitter) | Step 2 (git) | Step 3 (deps) | Step 4 (annotations)
                                    |
                              merge (main thread)
                                    |
NEW Step 4.5:          CallResolver(graph).resolve()
                                    |
Step 5:                Security labeling
```

Single line in `GraphBuilder.build()`:

```python
graph = CallResolver(graph).resolve()
```

---

## Symbol Table

Built during `CallResolver.__init__()` from existing graph nodes/edges.

### 1) Function Index

```python
# File -> functions defined in that file
_file_funcs: dict[str, list[Node]]
# {"src/main.c": [Node(func:src/main.c:add:1), Node(func:src/main.c:main:5)]}

# Name -> all definitions with that name
_name_to_defs: dict[str, list[Node]]
# {"add": [Node(func:src/main.c:add:1), Node(func:src/utils.c:add:10)]}

# Qualified name -> definition (from Class CONTAINS Function edges)
_qualified_to_def: dict[str, Node]
# {"Counter.increment": Node(func:src/counter.ts:increment:15)}
```

`_qualified_to_def` is populated by walking CONTAINS edges where source is a Class node
and target is a Function node: `f"{class_node.name}.{func_node.name}"`.

### 2) Import Map

```python
# (file, imported_name) -> source module/file path
_import_map: dict[tuple[str, str], str]
# {("src/app.ts", "foo"): "src/utils.ts", ("src/app.ts", "Bar"): "src/models.ts"}
```

### 3) File Set

```python
# All File node paths for module path resolution
_file_set: set[str]
```

---

## Import Parsing — Named Import Extraction

IMPORTS edges currently store `raw` property with the full import statement text.
A new `names` property will be added during extraction, storing comma-separated imported names.

Resolution step parses `names` property to build the import map.

### Per-Language Patterns

**JavaScript/TypeScript:**
```
import { foo, bar } from "./utils"     -> names: "foo,bar"    source: "./utils"
import { foo as f } from "./utils"     -> names: "f"          source: "./utils"  (alias used)
import Foo from "./utils"              -> names: "Foo"         source: "./utils"
import * as utils from "./utils"       -> names: ""            (wildcard skipped)
```

**Rust:**
```
use crate::utils::foo;                 -> names: "foo"         source: "crate::utils"
use crate::utils::{foo, bar};          -> names: "foo,bar"     source: "crate::utils"
```

**Java/Kotlin:**
```
import com.example.Foo;                -> names: "Foo"         source: "com.example"
import static com.example.Foo.bar;     -> names: "bar"         source: "com.example.Foo"
```

**Go:**
```
import "fmt"                           -> names: "fmt"         source: "fmt"
import alias "pkg/path"               -> names: "alias"       source: "pkg/path"
```

**C/C++:**
No named imports — `#include` is file-level. Only intra-file and global unique
fallback apply for C/C++.

---

## Resolution Chain Algorithm

`CallResolver.resolve()` iterates all `funcref:` nodes. For each, tries in order,
stops at first match:

### Step 1 — Qualifier Match

If funcref ID contains a dot (e.g., `funcref:Counter.increment`):
look up in `_qualified_to_def`. Direct match -> resolve.

### Step 2 — Intra-file Match

Find caller's file from CALLS edge -> caller node -> `file` property.
Search `_file_funcs[caller_file]` for name match.
- Single match -> resolve.
- Multiple matches -> pick closest by line number (nearest definition wins).

### Step 3 — Import Match

Look up `_import_map[(caller_file, callee_name)]` -> source module path.
Resolve module path to file path (see Module Path Resolution below).
Search `_file_funcs[resolved_file]` for name match.

### Step 4 — Global Unique

Look up `_name_to_defs[callee_name]`.
- Exactly one definition -> resolve.
- Multiple definitions -> leave unresolved (ambiguous).

### Resolution Action

Resolution is **per-caller**, not per-funcref. The same `funcref:foo` may be called
from multiple files — each caller resolves independently through the chain.

For each (caller, funcref) CALLS edge where a match is found:
1. Retarget the edge from `funcref:` node to the real `func:` node ID
2. Add `resolved: true` property to the retargeted edge
3. After all callers are processed, delete funcref nodes that have no remaining edges

### Statistics

Log at end: `"Resolved 8542/12000 calls (71.2%), 3458 unresolved (external/ambiguous)"`

---

## Module Path Resolution

`_resolve_module_path(caller_file, module_specifier)` converts import source
to a file path using only graph File nodes (no filesystem access).

### Relative Imports (JS/TS)

```
Caller: src/components/App.ts
Import: "./utils"
Candidates (try in order):
  1. src/components/utils.ts
  2. src/components/utils.js
  3. src/components/utils/index.ts
  4. src/components/utils/index.js
```

Check each candidate against `_file_set`. First hit wins.

### Package Imports (Java/Kotlin)

```
import com.example.utils.Foo -> com/example/utils/Foo.java or .kt
```

Convert dots to path separators, search in `_file_set`.

### Crate Imports (Rust)

```
use crate::utils::foo -> src/utils.rs or src/utils/mod.rs
```

### Go Imports

```
import "myproject/utils" -> files in utils/ directory
```

### External/Stdlib

`"react"`, `"fmt"`, `"std::io"` etc. will not match any File node -> skip.
Associated funcref nodes remain unresolved.

---

## Qualifier Preservation (Extraction-Side Change)

### Current Behavior

`_get_callee_name()` returns `str`, strips qualifiers:
- `obj.method()` -> `"method"` (qualifier lost)

### New Behavior

`_get_callee_name()` returns `tuple[str, str | None]`:

```python
def _get_callee_name(self, node, source) -> tuple[str, str | None]:
    """Return (name, qualifier). qualifier is None if no receiver."""
```

| Call | name | qualifier |
|------|------|-----------|
| `obj.method()` | `"method"` | `"obj"` |
| `Counter.increment()` | `"increment"` | `"Counter"` |
| `namespace::func()` | `"func"` | `"namespace"` |
| `foo()` | `"foo"` | `None` |
| `self.bar()` | `"bar"` | `None` (self/this/super skipped) |
| `this.bar()` | `"bar"` | `None` |

### funcref ID Format

- With qualifier: `funcref:Counter.increment`
- Without qualifier: `funcref:foo` (current behavior preserved)

### CALLS Edge Property

```python
graph.add_edge(caller_id, callee_id, EdgeType.CALLS, qualifier="Counter")
```

---

## Files Changed

### New Files

| File | Description |
|------|-------------|
| `archgraph/extractors/call_resolver.py` | `CallResolver` class, resolution chain, import map builder |
| `tests/test_call_resolver.py` | All resolution tests |

### Modified Files

| File | Change |
|------|--------|
| `archgraph/extractors/treesitter.py` | `_get_callee_name()` returns tuple, qualifier preservation, IMPORTS `names` property |
| `archgraph/graph/builder.py` | Add Step 4.5 `CallResolver` invocation after Group A merge |
| `archgraph/graph/schema.py` | Add `resolved` edge property if needed |

---

## Test Strategy

All tests run in-memory with `GraphData`, no Neo4j required.

| # | Test Class | Cases |
|---|-----------|-------|
| 1 | TestSymbolTable | func index, qualified index, import map construction |
| 2 | TestQualifierMatch | `funcref:Counter.increment` -> correct class method |
| 3 | TestIntraFileMatch | same-file call resolution, line proximity tiebreak |
| 4 | TestImportMatch | JS named import, Rust use, Java import, Go import |
| 5 | TestGlobalUnique | single def -> resolves, multiple defs -> unresolved |
| 6 | TestModulePathResolve | relative path, index.ts fallback, package->dir conversion |
| 7 | TestQualifierExtraction | `_get_callee_name()` returns correct tuple, self/this skip |
| 8 | TestUnresolvedRemain | stdlib/external calls stay as funcref |
| 9 | TestResolutionStats | log output shows correct statistics |
| 10 | TestIntegration | multi-file TypeScript project, end-to-end extraction + resolution |
