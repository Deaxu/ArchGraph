# ArchGraph

Kaynak kod graph extraction & Cypher query tool for reverse engineering.
Açık kaynak kütüphanelerin kapsamlı graph yapısını çıkarıp Neo4j'de saklayan bir extraction pipeline + rlm-agent için Cypher sorgusu çalıştıran bir BaseTool.

## Proje Yapısı

```
archgraph/
├── cli.py                         # Click CLI — extract, query, stats, schema komutları + GitHub URL desteği
├── config.py                      # Tüm sabitler, dil map'leri, güvenlik pattern'leri, ExtractConfig
├── extractors/
│   ├── base.py                    # BaseExtractor ABC
│   ├── treesitter.py              # Tree-sitter çok dilli parser (C/C++/Rust/Java/Go/JS/TS/Swift/Kotlin/ObjC)
│   ├── git.py                     # Commit geçmişi + numstat (lines_added/deleted), yazar, tag, güvenlik fix tespiti
│   ├── dependencies.py            # 10 paket yöneticisi: Cargo.toml, go.mod, package.json, gradle, Podfile, CMake, vcpkg, conan, Package.swift
│   ├── annotations.py             # TODO/HACK/UNSAFE/FIXME/BUG/XXX/SECURITY/VULNERABILITY tarayıcı
│   ├── security_labels.py         # Otomatik etiketleme: input_source, dangerous_sink, allocator, crypto, parser, unsafe
│   ├── clang.py                   # Faz 2 — derin C/C++ analizi (CFG, data flow, taint, macro, typedef, pointer)
│   └── deep/                      # Faz 3 — tree-sitter deep analysis (Rust, Java, Go, Kotlin, Swift)
│       ├── engine.py              # CFG builder, reaching definitions, data flow, taint
│       ├── lang_spec.py           # LangSpec dataclass + REGISTRY
│       ├── rust.py / java.py / go.py / kotlin.py / swift.py
├── graph/
│   ├── schema.py                  # Node/Edge dataclass'ları, NodeLabel/EdgeType sabitleri
│   ├── builder.py                 # Tüm extractor'ları orkestre eden 8-adım pipeline
│   └── neo4j_store.py             # Neo4j bağlantı, batch import, index, sorgu
├── enrichment/
│   └── churn.py                   # Git churn (dosya değişim sıklığı) zenginleştirme
└── tool/
    └── archgraph_tool.py          # rlm-agent tool: tek query() metodu, şema description'da
```

## Geliştirme Ortamı

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Testler

```bash
# Tüm testler (93 test — 89 passed, 4 skipped)
pytest tests/ -v

# Tek modül
pytest tests/test_treesitter.py -v
pytest tests/test_extractors.py -v
pytest tests/test_clang.py -v
pytest tests/test_deep.py -v
pytest tests/test_builder.py -v
pytest tests/test_schema.py -v
pytest tests/test_tool.py -v
```

Test dosyaları Neo4j gerektirmez. Tree-sitter ve git testleri tmp_path fixture ile gerçek parse/commit yapar.

## CLI Kullanımı

```bash
# Lokal dizinden graph çıkar ve Neo4j'ye aktar
archgraph extract /path/to/repo --languages c,cpp,rust --neo4j-uri bolt://localhost:7687

# GitHub URL'den direkt klonla ve extract et
archgraph extract https://github.com/madler/zlib --languages c,cpp --clear-db

# Belirli branch + shallow clone
archgraph extract https://github.com/user/repo --branch main --depth 100

# Cypher sorgusu çalıştır
archgraph query "MATCH (f:Function {is_input_source: true}) RETURN f.name LIMIT 10"

# İstatistikler
archgraph stats

# Şema bilgisi
archgraph schema
```

## Kod Kuralları

- Python 3.11+, type hint zorunlu
- Ruff formatter, line-length 100
- Her extractor BaseExtractor'dan türer, `extract(repo_path) -> GraphData` döner
- Node ID formatı: `{tip}:{yol}:{isim}:{satır}` (ör. `func:src/main.c:parse_data:42`)
- Edge'ler `(source_id, target_id, type)` tuple ile unique
- Edge'ler property taşıyabilir (ör. MODIFIED_IN: `lines_added`, `lines_deleted`)
- `GraphData.deduplicate()` pipeline sonunda çağrılır
- Security label'lar `config.py`'deki frozenset'lerle eşleşir
- Neo4j importta `_Node` label'ı tüm node'lara eklenir (cross-label query için)
- Neo4j'de `_id` property unique constraint taşır

## Graph Şeması — Önemli Edge Property'leri

| Edge | Property | Açıklama |
|------|----------|----------|
| MODIFIED_IN | lines_added, lines_deleted | Commit başına dosya değişim istatistikleri |
| DATA_FLOWS_TO | from_var, to_var, from_line, to_line | Veri akışı detayları |

## Git Extraction Detayları

- Commit node: `hash, message, date, total_insertions, total_deletions, files_changed`
- MODIFIED_IN edge: `lines_added, lines_deleted` (per-file per-commit)
- SecurityFix → AFFECTS → File (güvenlik fix'i hangi dosyaları etkiledi)
- Tag: full hash ile commit node'a bağlanır (TAGGED_AS)
- `--numstat` parser: blank-line tolerant, commit header'da flush

## rlm-agent Entegrasyonu

`archgraph_tool.py` standalone çalışır (rlm-agent yoksa stub BaseTool kullanır).

**API:** Tek metod — `query(cypher, params)`. Graph şeması (node label'lar, edge type'lar, property'ler, ID formatı) `tool.description`'a gömülü — agent context'te görür, discovery çağrısına gerek yok.

```python
from archgraph.tool.archgraph_tool import ArchGraphTool

with ArchGraphTool(neo4j_uri="bolt://localhost:7687") as tool:
    results = tool.query("MATCH (f:Function {is_input_source: true}) RETURN f.name, f.file")
```

Entry point kaydı için `pyproject.toml`'a `[project.entry-points."rlm_agent.tools"]` eklenecek (henüz eklenmedi, rlm-agent dependency'si olmadan).

## Mevcut Faz Durumu

Geliştirme fazları `docs/ROADMAP.md` dosyasında takip edilir.

## Doğrulanan Ölçek

| Proje | Dosya | Node | Edge | Commit | Yazar |
|-------|-------|------|------|--------|-------|
| zlib (~50K LOC) | 79 | 3,577 | 11,100 | 1,020 | 89 |
