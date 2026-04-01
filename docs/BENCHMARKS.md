# Benchmarks

End-to-end extraction results on real open-source projects.

## Results

| Project | Language | Files | Nodes | Edges | CALLS | Resolution | Time |
|---------|----------|-------|-------|-------|-------|------------|------|
| [zod](https://github.com/colinhacks/zod) | TypeScript | 394 | 6,654 | 11,972 | 4,768 | SCIP 100% | ~20s |
| [click](https://github.com/pallets/click) | Python | 62 | 1,210 | 2,007 | 567 | SCIP 100% | ~50s |
| [memchr](https://github.com/BurntSushi/memchr) | Rust | 64 | 7,707 | 8,415 | 259 | SCIP 100% | ~14s |
| [gocron](https://github.com/go-co-op/gocron) | Go | 21 | 850 | 1,855 | 1,026 | SCIP 100% | ~5s |
| [gson](https://github.com/google/gson) | Java | 259 | 9,217 | 20,979 | 2,622 | Heuristic | ~15s |
| [lodash](https://github.com/lodash/lodash) | JavaScript | 27 | 691 | 683 | 19 | SCIP 100% | ~14s |

*Windows 11, Python 3.13, 8 workers. Extraction only (no git/deps/CVE). Java SCIP falls back to heuristic on multi-module Maven projects.*

## Call Resolution

Every CALLS edge carries metadata so you know how reliable it is:

| Source | Confidence | How |
|--------|-----------|-----|
| `scip` | High | Compiler-backed cross-references with full type information |
| `heuristic` | Lower | Name-based matching (4-level fallback: qualifier, intra-file, import, global unique) |

**SCIP** runs the language's own compiler to resolve calls -- it knows *exactly* which function is being called. **Heuristic** matches by name and can pick the wrong target in projects with common method names.

Use `search_calls(source="scip")` to only get compiler-verified call chains.

## Notes

- SCIP indexers are downloaded and installed automatically on first use
- Java SCIP (`scip-java`) requires a single-module Maven/Gradle project; multi-module projects fall back to heuristic
- Time includes SCIP indexing; tree-sitter parsing alone is typically <2s for all projects above
