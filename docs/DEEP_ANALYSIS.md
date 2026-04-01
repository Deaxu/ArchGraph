# Deep Analysis

ArchGraph provides intra-procedural deep analysis for 7 languages across two engines.

> **Note:** Python and TypeScript/JavaScript use SCIP compiler-backed resolution for cross-file call accuracy (~82%) instead of deep analysis. Deep analysis focuses on CFG, data flow, and taint tracking for languages where these are most relevant.

## C/C++ via libclang

Requires `pip install -e ".[clang]"` (libclang 18.1+).

Enable with `--include-clang` or `include_clang=True`.

### Capabilities

| Feature | Description | Graph Output |
|---------|-------------|--------------|
| Control Flow Graph | If/else, while/for, return statements | `BasicBlock` nodes + `BRANCHES_TO` edges |
| Data Flow | Reaching definitions (iterative worklist) | `DATA_FLOWS_TO` self-edges on Function |
| Taint Tracking | Input source → variable chain → dangerous sink | `TAINTS` edges (funcref → funcref) |
| Macro Expansion | Tracks macro instantiation sites | `EXPANDS_MACRO` edges |
| Typedef Resolution | Resolves full typedef chain to base type | `resolved_type` property on TypeAlias |
| Pointer Analysis | void* cast and pointer arithmetic detection | `has_void_cast`, `has_pointer_arith` flags |

### CFG Construction

The CFG builder creates `BasicBlock` nodes connected by `BRANCHES_TO` edges:

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Block 0  │────▶│  Block 1  │────▶│  Block 3  │
│ (entry)   │     │ (then)    │     │ (join)    │
└──────────┘     └──────────┘     └──────────┘
      │                                  ▲
      │           ┌──────────┐           │
      └──────────▶│  Block 2  │──────────┘
                  │ (else)    │
                  └──────────┘
```

### Data Flow Example

For a function:
```c
void process(char *input) {
    int len = strlen(input);     // len defined from input
    char *buf = malloc(len);     // buf defined from len
    memcpy(buf, input, len);     // buf, input, len used
}
```

Generated edges:
- `DATA_FLOWS_TO (from_var=input, to_var=len, from_line=1, to_line=2)`
- `DATA_FLOWS_TO (from_var=len, to_var=buf, from_line=2, to_line=3)`

### Taint Tracking

Taint propagation traces data from `INPUT_SOURCES` through variable assignments to `DANGEROUS_SINKS`:

```
recv() → buf → processed_buf → memcpy()
  ↑ source                        ↑ sink
```

Generates: `TAINTS (funcref:path:recv:0 → funcref:path:memcpy:0)`

## Rust, Java, Go, Kotlin, Swift via tree-sitter

Enable with `--include-deep` or `include_deep=True`.

These languages use a shared deep analysis engine (`deep/engine.py`) with language-specific specifications (`deep/lang_spec.py`).

### Supported Languages & Optional Dependencies

| Language | Status | Extra Dependency |
|----------|--------|------------------|
| Rust | Built-in | tree-sitter-rust (required) |
| Java | Built-in | tree-sitter-java (required) |
| Go | Built-in | tree-sitter-go (required) |
| Kotlin | Optional | `pip install -e ".[kotlin]"` |
| Swift | Optional | `pip install -e ".[swift]"` |

### Capabilities

Same as C/C++ (CFG, data flow, taint) plus language-specific pattern detection:

| Language | Detected Patterns | Function Properties |
|----------|-------------------|---------------------|
| Rust | unsafe blocks, transmute, unwrap, raw pointer deref | `has_unsafe_block`, `has_transmute`, `has_force_unwrap` |
| Java | reflection, serialization, synchronized blocks, native methods | `has_reflection`, `has_serialization`, `has_synchronized`, `has_native` |
| Go | goroutines, defer, channel operations, unsafe pointers, error checks | `has_goroutine`, `has_channel_op`, `has_defer`, `has_unsafe_pointer`, `has_error_check` |
| Kotlin | coroutines, force unwrap (!!), safe calls (?.) | `has_coroutine`, `has_force_unwrap`, `has_safe_call` |
| Swift | force unwrap (!), optional chaining (?.), force try (try!), weak refs | `has_force_unwrap`, `has_optional_chain`, `has_force_try`, `has_weak_ref` |

### Example Queries

```cypher
-- Find Rust functions with unsafe blocks
MATCH (f:Function {has_unsafe_block: true})
RETURN f.name, f.file, f.line_start

-- Find Go functions spawning goroutines
MATCH (f:Function {has_goroutine: true})
RETURN f.name, f.file

-- Find Java native methods (JNI boundary)
MATCH (f:Function {has_native: true})
RETURN f.name, f.file

-- CFG for a specific function
MATCH (f:Function {name: "process"})-[:CONTAINS]->(bb:BasicBlock)
OPTIONAL MATCH (bb)-[:BRANCHES_TO]->(next:BasicBlock)
RETURN bb.block_index, bb.stmt_count, collect(next.block_index) AS successors
ORDER BY bb.block_index
```
