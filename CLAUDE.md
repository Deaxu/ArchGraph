# ArchGraph

Kaynak kod graph extraction & Cypher query tool for reverse engineering.

## Geliştirme Ortamı

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Testler

```bash
# Tüm testler (212 collected — 212 passed, 22 skipped)
pytest tests/ -v
```

Test dosyaları Neo4j gerektirmez. Tree-sitter ve git testleri `tmp_path` fixture ile gerçek parse/commit yapar.

## Kod Kuralları

- Python 3.11+, type hint zorunlu
- Ruff formatter, line-length 100
- Her extractor `BaseExtractor`'dan türer, `extract(repo_path, **kwargs) -> GraphData` döner
- Extractor'lara `workers` kwarg ile parallelism geçirilir (thread-local parser)
- Node ID formatı: `{tip}:{yol}:{isim}:{satır}` (ör. `func:src/main.c:parse_data:42`)
- Edge'ler `(source_id, target_id, type)` tuple ile unique
- `GraphData.deduplicate()` pipeline sonunda çağrılır
- `GraphData.merge()` tek thread'de çağrılmalı (futures.result() sonrası)
- Security label'lar `config.py`'deki frozenset'lerle eşleşir
- Neo4j importta `_Node` label'ı tüm node'lara eklenir (cross-label query için)
- Neo4j'de `_id` property unique constraint taşır

## Thread Safety

- `ts.Language` objeleri thread-safe → paylaşılabilir
- `ts.Parser` objeleri thread-safe DEĞİL → `threading.local()` ile thread-başına instance
- libclang `Index` thread-safe değil → her thread kendi `Index.create()`
- Pipeline merge işlemleri ana thread'de yapılır

## Kilit Dosyalar

| Dosya | Açıklama |
|-------|----------|
| `archgraph/config.py` | Tüm sabitler, güvenlik pattern'leri, `ExtractConfig` dataclass |
| `archgraph/graph/builder.py` | 11-adım + Step 4.5 pipeline orkestrasyon (parallel/sequential) |
| `archgraph/graph/schema.py` | `Node`/`Edge` dataclass, `NodeLabel`/`EdgeType` sabitleri |
| `archgraph/graph/neo4j_store.py` | Neo4j batch import, `_Node` label, `_id` unique |
| `archgraph/extractors/treesitter.py` | Ana extractor, 10 dil, thread-local parser |
| `archgraph/extractors/clang.py` | libclang deep analysis (CFG, data flow, taint) |
| `archgraph/extractors/deep/` | Tree-sitter deep analysis (Rust, Java, Go, Kotlin, Swift) |
| `archgraph/enrichment/cve.py` | CVE enrichment — OSV API batch query |
| `archgraph/tool/archgraph_tool.py` | rlm-agent tool (11 tool method, BaseTool bağımlılığı yok) |
| `archgraph/api.py` | Python API — `ArchGraph` sınıfı, tüm tool'ların programmatik erişimi |
| `archgraph/extractors/scip_resolver.py` | SCIP compiler-backed call resolution (TS/JS/Rust/Go/Java/Python) |
| `archgraph/extractors/call_resolver.py` | Heuristic call resolution (SCIP fallback, 4-seviye zincir) |
| `archgraph/mcp/server.py` | MCP server — 12 tool, 4 resource |

## Dokümantasyon

Detaylı dökümantasyon `docs/` altında:

- `docs/ARCHITECTURE.md` — Proje yapısı, pipeline, graph schema, node/edge tipleri
- `docs/CLI.md` — Tüm komutlar ve option'lar
- `docs/DEEP_ANALYSIS.md` — CFG, data flow, taint, dil-bazlı pattern'ler
- `docs/SECURITY.md` — Security labeling, CVE enrichment, örnek sorgular
- `docs/AGENT.md` — rlm-agent entegrasyonu, API referansı
- `docs/ROADMAP.md` — Faz 1-4 durumu
