# Code Body Storage in Graph

**Date**: 2026-03-31
**Status**: Approved

## Summary

Store actual source code as `body` property on Function, Class, Struct, Interface, and Enum nodes. This elevates ArchGraph from a structural metadata graph to a full code intelligence graph where AI agents can read source code directly from Neo4j without filesystem access.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Storage granularity | Function/Class level (not BasicBlock) | Agents work best with complete function bodies; CFG-level fragmentation adds complexity |
| Function body content | Full text (signature + body) | Agents see decorators, visibility, params, return type, and implementation in one read |
| Class body content | Shell (fields + method signatures, bodies replaced with `{ ... }`) | Prevents huge class nodes; method bodies live on Function nodes |
| Storage mechanism | Direct `body` property on nodes | Simplest approach; Macro nodes already use this pattern |
| Default | `include_body=True` (opt-out via `--no-body`) | Code bodies are the primary value-add; users who want smaller graphs can disable |
| Truncation | `max_body_size=51200` (50KB), marker appended | Prevents extreme outliers from bloating the graph |

## Node Types & Body Content

| Node Type | body Content | Typical Size |
|-----------|-------------|-------------|
| Function | Full source (signature + body) | 500B - 10KB |
| Class | Shell (fields + method sigs, bodies `{ ... }`) | 200B - 5KB |
| Struct | Full source | 50B - 1KB |
| Interface | Full source | 100B - 500B |
| Enum | Full source | 50B - 500B |
| Macro | Already has `body` — no change | — |

## New Properties

Added to nodes that carry code:

| Property | Type | Description |
|----------|------|-------------|
| `body` | string | Source code text |
| `body_lines` | int | Line count of the body |
| `body_truncated` | bool | True if body was truncated due to size limit |

## Architecture

```
TreeSitter parse -> AST node + source bytes
                        |
               _extract_function()
                        |
          +-------------+-------------+
          | Existing: name, params,   |
          | line_start, return_type   |
          |                           |
          | NEW: body = full text     |
          |      body_lines = count   |
          |      body_truncated?      |
          +---------------------------+
                        |
               Neo4j Function node
                        |
          MCP "source" tool / Python API
```

## Files to Change

| File | Change |
|------|--------|
| `archgraph/config.py` | Add `include_body: bool = True`, `max_body_size: int = 51_200` to `ExtractConfig` |
| `archgraph/cli.py` | Add `--no-body`, `--max-body-size` options to `extract` command |
| `archgraph/extractors/treesitter.py` | Add body to `_extract_function`, `_extract_class`, `_extract_struct`, `_extract_interface`, `_extract_enum`; new `_extract_class_shell()` helper |
| `archgraph/mcp/server.py` | New `source` tool; filter body from `context` tool; add `body_coverage` to `stats` |
| `archgraph/graph/neo4j_store.py` | New `get_source()` convenience method |
| `archgraph/tool/archgraph_tool.py` | New `source()` method; update `_DESCRIPTION` with body properties |
| `docs/ARCHITECTURE.md` | Document body properties in schema tables |
| `tests/` | New tests for body extraction, class shell, truncation, MCP source tool |

## Class Shell Algorithm

```python
def _extract_class_shell(node, source, lang, lang_types):
    """Class text with method bodies replaced by { ... }."""
    class_bytes = bytearray(source[node.start_byte:node.end_byte])
    offset = node.start_byte

    # Find nested function bodies, replace in reverse order
    replacements = []
    for child in walk_descendants(node):
        if child.type in lang_types.get("function_def", []):
            body = find_body_node(child)
            if body:
                inner_start = body.start_byte + 1 - offset  # after {
                inner_end = body.end_byte - 1 - offset      # before }
                replacements.append((inner_start, inner_end))

    for start, end in sorted(replacements, reverse=True):
        class_bytes[start:end] = b" ... "

    return class_bytes.decode("utf-8", errors="replace")
```

## API Surface

| Layer | Access | body Behavior |
|-------|--------|---------------|
| `Neo4jStore.get_source(id)` | Core Python | Returns body |
| `Neo4jStore.query(cypher)` | Core Python | User controls via Cypher |
| `ArchGraphTool.source(id)` | rlm-agent | Returns body |
| `ArchGraphTool.query(cypher)` | rlm-agent | User controls via Cypher |
| MCP `source` tool | MCP | Returns body |
| MCP `context` tool | MCP | body **excluded** |
| MCP `query`/`cypher` tool | MCP | User controls via Cypher |

### MCP `source` Tool

```json
{
    "name": "source",
    "description": "Get source code of a function, class, struct, or other symbol",
    "inputSchema": {
        "type": "object",
        "properties": {
            "symbol_id": {
                "type": "string",
                "description": "Symbol node ID (e.g. 'func:src/auth.c:validate:42')"
            }
        },
        "required": ["symbol_id"]
    }
}
```

Response format:
```json
{
    "symbol_id": "func:src/auth.c:validate:42",
    "name": "validate",
    "file": "src/auth.c",
    "language": "c",
    "line_start": 42,
    "line_end": 67,
    "body": "int validate(const char *token) {\n    if (!token) return -1;\n    ...\n}",
    "body_truncated": false,
    "body_lines": 26
}
```

## Truncation Strategy

- `max_body_size` in bytes (default 51,200 = 50KB)
- If exceeded: truncate at last complete line within limit
- Append `\n// ... [truncated: {n} total lines]`
- Set `body_truncated = true` on the node

## Test Plan

| Test | Validates |
|------|----------|
| `test_function_body_extraction` | Body correct for each language (C, Rust, Java, Go, JS, TS) |
| `test_class_shell_extraction` | Method bodies replaced with `{ ... }`, fields preserved |
| `test_body_truncation` | Truncation at `max_body_size`, marker appended, flag set |
| `test_no_body_flag` | `include_body=False` produces no body on any node |
| `test_struct_interface_enum_body` | Small node types carry full source |
| `test_mcp_source_tool` | MCP `source` tool returns correct response |
| `test_mcp_context_no_body` | MCP `context` tool excludes body |
| `test_neo4j_get_source` | `Neo4jStore.get_source()` returns body, None for missing ID |
| `test_archgraph_tool_source` | rlm-agent `source()` method works |

## Edge Cases

| Case | Solution |
|------|----------|
| Empty function body (`fn noop() {}`) | `body = "fn noop() {}"`, `body_lines = 1` |
| Multi-line string literals | Tree-sitter byte range captures as-is |
| Unicode / binary characters | `decode("utf-8", errors="replace")` already in use |
| Anonymous / lambda functions | Body stored, name uses `anonymous_{line}` pattern |
| Nested class methods | Method has own Function node with body; parent class shell shows `{ ... }` |
| `include_body=True` + deep analysis off | Body stored regardless — independent features |
| Incremental extraction | Changed files' function bodies updated normally |

## Performance Impact

- Graph size increase: ~4-5x (15MB -> 60-80MB for a 50K node project)
- Query performance: unaffected when using Cypher projection (don't `RETURN n`, use `RETURN n.name, n.file`)
- Extraction time: negligible — body is extracted from already-parsed source bytes
- Test suite: zero impact — existing tests don't check for body absence
