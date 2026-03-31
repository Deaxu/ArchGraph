# SCIP-Based Call Resolution — Design Spec

**Date:** 2026-03-31
**Status:** Approved

## Problem

The heuristic CallResolver resolves 43.5% of calls using regex-based import parsing
and name matching. SCIP (Sourcegraph Code Intelligence Protocol) achieves 81.9% using
compiler-backed cross-references. We're reinventing module resolution poorly when
every language already has a compiler that does it perfectly.

## Goals

1. Replace heuristic CALLS edge generation with SCIP compiler-backed references
2. Auto-install and run SCIP indexers as part of the extraction pipeline
3. Fall back to heuristic resolver for languages without SCIP indexer support
4. Plugin-ready architecture so adding new language indexers is trivial

## Non-Goals

- Runtime/dynamic dispatch resolution
- Cross-repo dependency resolution
- Modifying tree-sitter extraction (it still produces funcref: nodes as before)

---

## Architecture

### New Module

`archgraph/extractors/scip_resolver.py` — contains `ScipResolver`, `ScipIndexer`
protocol, `TypeScriptIndexer`, and `INDEXER_REGISTRY`.

### Pipeline Position

Same position as current CallResolver (Step 4.5), but ScipResolver runs first:

```
Step 1-4:    Tree-sitter, Git, Deps, Annotations (unchanged)
                        ↓
Step 4.5:    ScipResolver
               ├─ For each language in config:
               │    ├─ INDEXER_REGISTRY has indexer? → install if needed, run, parse .scip
               │    └─ No indexer? → skip (this language falls through to heuristic)
               ├─ Generate CALLS edges from SCIP references (resolved: true)
               ├─ Remove old funcref: nodes/edges for SCIP-covered languages
               └─ For non-SCIP languages: CallResolver heuristic fallback
                        ↓
Step 5:      Security labeling
```

### Class Structure

```python
class ScipIndexer(Protocol):
    """Interface for per-language SCIP indexers."""
    language: str
    def install(self, repo_path: Path) -> bool: ...
    def index(self, repo_path: Path) -> Path | None: ...  # returns .scip path or None

class TypeScriptIndexer:
    """SCIP indexer for TypeScript/JavaScript."""
    language = "typescript"
    # npm install @sourcegraph/scip-typescript (repo-local)
    # npx scip-typescript index --output .archgraph/index.scip

# TODO indexers (same interface, add to registry):
# class PythonIndexer: ...      # pip install scip-python
# class JavaIndexer: ...        # scip-java JAR download
# class RustIndexer: ...        # rust-analyzer --scip
# class GoIndexer: ...          # go install github.com/sourcegraph/scip-go
# class ClangIndexer: ...       # scip-clang binary

INDEXER_REGISTRY: dict[str, type[ScipIndexer]] = {
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

class ScipResolver:
    """SCIP-based call resolution — compiler-backed accuracy."""
    def __init__(self, graph: GraphData, repo_path: Path, languages: list[str]): ...
    def resolve(self) -> GraphData: ...
```

---

## SCIP Index Parsing

### Proto

`scip_pb2.py` is pre-compiled from `scip.proto` and committed to the repo.
No runtime `protoc` dependency.

### Data Extraction

From the parsed SCIP Index:

**1) Definition Map:**
```python
# symbol string → (file, line, name)
sym_to_def: dict[str, tuple[str, int, str]] = {}
for doc in index.documents:
    for occ in doc.occurrences:
        if occ.symbol_roles & 1:  # Definition bit
            # extract name: last segment after / or . — e.g. "npm pkg `file`/funcName()." → "funcName"
            name = occ.symbol.rstrip(".").rsplit("/", 1)[-1].rstrip("().").split("#")[-1]
            sym_to_def[occ.symbol] = (doc.relative_path, occ.range[0], name)
```

**2) Caller Detection:**
To determine which function a reference is inside, build a line-range index
from tree-sitter Function nodes:

```python
# file → sorted list of (line_start, line_end, func_node_id)
func_ranges: dict[str, list[tuple[int, int, str]]]
```

For each reference occurrence at `(file, line)`, binary search `func_ranges[file]`
to find the enclosing function → that's the caller.

**3) CALLS Edge Generation:**
For each reference occurrence where `sym_to_def[symbol]` exists:
- Find caller function (enclosing function at reference line)
- Find target function (definition from sym_to_def)
- Match target to existing `func:` node in graph (by file + name + line proximity)
- Create CALLS edge with `resolved: true, source: "scip"`

**4) Cleanup:**
For languages covered by SCIP:
- Remove all `funcref:` nodes and their CALLS edges
- SCIP-generated edges replace them entirely

---

## Auto-Install Flow

### TypeScriptIndexer

```
install(repo_path):
  1. Check: npm available? (shutil.which("npm"))
  2. Check: npx scip-typescript --version works?
  3. If not: run "npm install --save-dev @sourcegraph/scip-typescript" in repo
  4. If npm install fails: try "npm install -g @sourcegraph/scip-typescript"
  5. Return True if scip-typescript now available, False otherwise

index(repo_path):
  1. Check: tsconfig.json exists? If not, use --infer-tsconfig
  2. Run: npx scip-typescript index --output .archgraph/index.scip
  3. If success: return Path(".archgraph/index.scip")
  4. If failure: log warning, return None (heuristic fallback)
```

### Future Indexers (TODO)

Each follows the same pattern:
- Check if tool available
- If not, install via the language's package manager
- Run indexer with output to `.archgraph/`
- Return path or None

---

## Files

### New Files

| File | Description |
|------|-------------|
| `archgraph/extractors/scip_resolver.py` | ScipResolver, ScipIndexer protocol, TypeScriptIndexer, INDEXER_REGISTRY |
| `archgraph/extractors/scip_pb2.py` | Pre-compiled SCIP protobuf (committed) |
| `tests/test_scip_resolver.py` | All SCIP resolution tests |

### Modified Files

| File | Change |
|------|--------|
| `archgraph/graph/builder.py` | Step 4.5: ScipResolver first, CallResolver fallback for non-SCIP languages |

### Unchanged Files

| File | Reason |
|------|--------|
| `archgraph/extractors/call_resolver.py` | Stays as fallback for non-SCIP languages |
| `archgraph/extractors/treesitter.py` | Still produces funcref: nodes (unchanged) |

---

## Test Strategy

All unit tests use mock SCIP data (no real indexer needed).

| # | Test Class | Cases |
|---|-----------|-------|
| 1 | TestScipParsing | Parse mini .scip protobuf, sym_to_def map correct |
| 2 | TestCallerDetection | Reference line → correct enclosing function |
| 3 | TestEdgeGeneration | SCIP references produce correct CALLS edges |
| 4 | TestFuncrefCleanup | Old funcref nodes/edges removed for SCIP-covered languages |
| 5 | TestIndexerInstall | TypeScriptIndexer install/index with mock subprocess |
| 6 | TestFallback | No SCIP indexer → heuristic CallResolver runs |
| 7 | TestIntegration | Real mini TS project, end-to-end SCIP resolution |

### POC Results (Validated)

| Metric | Heuristic | SCIP |
|--------|-----------|------|
| Resolution rate | 43.5% (32,954/75,837) | 81.9% (436,257/532,722) |
| Accuracy | Regex heuristic | Compiler-backed |
| Cross-file | Partial (import parsing) | Complete (type checker) |
