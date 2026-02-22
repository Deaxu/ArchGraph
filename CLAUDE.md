# ArchGraph

Kaynak kod graph extraction & Cypher query tool for reverse engineering.
Açık kaynak kütüphanelerin kapsamlı graph yapısını çıkarıp Neo4j'de saklayan bir extraction pipeline + rlm-agent için Cypher sorgusu çalıştıran bir BaseTool.

## Proje Yapısı

```
archgraph/
├── cli.py                         # Click CLI — extract, query, stats, schema komutları
├── config.py                      # Tüm sabitler, dil map'leri, güvenlik pattern'leri, ExtractConfig
├── extractors/
│   ├── base.py                    # BaseExtractor ABC
│   ├── treesitter.py              # Tree-sitter çok dilli parser (C/C++/Rust/Java/Go/JS/TS/Swift/Kotlin/ObjC)
│   ├── git.py                     # Commit geçmişi, yazar, tag, güvenlik fix tespiti
│   ├── dependencies.py            # 10 paket yöneticisi: Cargo.toml, go.mod, package.json, gradle, Podfile, CMake, vcpkg, conan, Package.swift
│   ├── annotations.py             # TODO/HACK/UNSAFE/FIXME/BUG/XXX/SECURITY/VULNERABILITY tarayıcı
│   ├── security_labels.py         # Otomatik etiketleme: input_source, dangerous_sink, allocator, crypto, parser, unsafe
│   └── clang.py                   # Faz 2 stub — derin C/C++ analizi (henüz implement edilmedi)
├── graph/
│   ├── schema.py                  # Node/Edge dataclass'ları, NodeLabel/EdgeType sabitleri
│   ├── builder.py                 # Tüm extractor'ları orkestre eden pipeline
│   └── neo4j_store.py             # Neo4j bağlantı, batch import, index, sorgu
├── enrichment/
│   └── churn.py                   # Git churn (dosya değişim sıklığı) zenginleştirme
└── tool/
    └── archgraph_tool.py          # rlm-agent tool: query(), schema(), stats() + kolaylık metodları
```

## Geliştirme Ortamı

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Testler

```bash
# Tüm testler
pytest tests/ -v

# Tek modül
pytest tests/test_treesitter.py -v
pytest tests/test_extractors.py -v
pytest tests/test_builder.py -v
pytest tests/test_schema.py -v
```

Test dosyaları Neo4j gerektirmez. Tree-sitter ve git testleri tmp_path fixture ile gerçek parse/commit yapar.

## CLI Kullanımı

```bash
# Repo'dan graph çıkar ve Neo4j'ye aktar
archgraph extract /path/to/repo --languages c,cpp,rust --neo4j-uri bolt://localhost:7687

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
- `GraphData.deduplicate()` pipeline sonunda çağrılır
- Security label'lar `config.py`'deki frozenset'lerle eşleşir
- Neo4j importta `_Node` label'ı tüm node'lara eklenir (cross-label query için)
- Neo4j'de `_id` property unique constraint taşır

## rlm-agent Entegrasyonu

`archgraph_tool.py` standalone çalışır (BaseTool import'u zorunlu değil). Kullanım:

```python
from archgraph.tool.archgraph_tool import ArchGraphTool

with ArchGraphTool(neo4j_uri="bolt://localhost:7687") as tool:
    sources = tool.find_attack_surface()
    paths = tool.find_dangerous_paths("recv", max_depth=5)
    fixes = tool.find_security_fixes()
```

Entry point kaydı için `pyproject.toml`'a `[project.entry-points."rlm_agent.tools"]` eklenecek (henüz eklenmedi, rlm-agent dependency'si olmadan).

## Mevcut Faz Durumu

Geliştirme fazları `docs/ROADMAP.md` dosyasında takip edilir.
