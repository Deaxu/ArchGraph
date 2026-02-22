# ArchGraph Geliştirme Yol Haritası

Durum ikonları: done, partial, planned, deferred

---

## Faz 1: Tree-sitter Yapısal Graph (Tüm Diller)

### Adım 1: Proje iskelet yapısı — DONE
- [x] pyproject.toml, dizin yapısı, temel config
- [x] Venv, bağımlılıklar, CLI entry point

### Adım 2: Graph şeması ve Neo4j store — DONE
- [x] `schema.py` — Node/Edge dataclass, NodeLabel/EdgeType sabitleri
- [x] `neo4j_store.py` — bağlantı, batch import, index oluşturma, sorgu
- [x] `GraphData` — merge, deduplicate, stats

### Adım 3: Tree-sitter extractor (C/C++) — DONE
- [x] `treesitter.py` — AST parse, fonksiyon/class/struct/import extraction
- [x] CALLS edge'leri (call_expression yürüme)
- [x] CONTAINS edge'leri (file→func, class→method)
- [x] Export detection (static, pub, public, uppercase)
- [x] Parameter extraction

### Adım 4: Tree-sitter diğer diller — DONE
- [x] Rust — function_item, struct_item, trait_item, impl_item, use_declaration
- [x] Java — method_declaration, class_declaration, interface_declaration
- [x] Go — function_declaration, method_declaration, type_declaration
- [x] JavaScript — function_declaration, arrow_function, class_declaration
- [x] TypeScript — interface_declaration, type_alias_declaration, enum_declaration
- [x] Kotlin, Swift, Objective-C — grammar tanımları (opsiyonel bağımlılık)

### Adım 5: Git extractor — DONE
- [x] `git.py` — commit geçmişi, yazar, parent chain
- [x] File→Commit mapping (MODIFIED_IN)
- [x] Tag extraction (TAGGED_AS)
- [x] Security commit tespiti (CVE, buffer overflow, use-after-free, vb.)
- [x] `churn.py` — dosya değişim sıklığı enrichment

### Adım 6: Dependency extraction — DONE
- [x] Cargo.toml (tam TOML parse + regex fallback)
- [x] go.mod
- [x] package.json
- [x] build.gradle / build.gradle.kts
- [x] Podfile
- [x] CMakeLists.txt (find_package + FetchContent)
- [x] conanfile.txt
- [x] vcpkg.json
- [x] Package.swift

### Adım 7: Annotations & security labels — DONE
- [x] `annotations.py` — TODO/HACK/UNSAFE/FIXME/BUG/XXX/SECURITY/VULNERABILITY
- [x] `security_labels.py` — input_source, dangerous_sink, allocator, crypto, parser, unsafe
- [x] Etiket kümeleri `config.py`'de frozenset olarak tanımlı

### Adım 8: Graph builder pipeline — DONE
- [x] `builder.py` — tüm extractor'ları sırayla çalıştır, merge, deduplicate
- [x] `cli.py` — `archgraph extract` komutu, tüm flag'ler

### Adım 9: rlm-agent tool — DONE
- [x] `archgraph_tool.py` — query(), schema(), stats()
- [x] Kolaylık metodları: find_attack_surface(), find_dangerous_paths(), find_security_fixes(), find_high_churn_files()
- [ ] Entry point kaydı (`pyproject.toml` — rlm-agent bağımlılığı olmadan bekleniyor)

### Adım 10: Testler — DONE
- [x] `test_schema.py` — 7 test (node/edge/graphdata)
- [x] `test_treesitter.py` — 15 test (C parse, Rust parse, edge cases)
- [x] `test_extractors.py` — 20 test (dependency, annotation, security label, git)
- [x] `test_builder.py` — 2 test (full pipeline integration)
- [x] `test_tool.py` — 2 test (tool property/creation)
- [x] Toplam: 44/44 test geçiyor

---

## Faz 2: Clang Deep Analysis (C/C++) — DONE

### Adım 11: Data flow / taint tracking — DONE
- [x] `clang.py` — libclang AST traversal (tam implementasyon)
- [x] DATA_FLOWS_TO edge'leri (variable→variable veri akışı, reaching definitions)
- [x] TAINTS edge'leri (tainted input yayılma zinciri: INPUT_SOURCE→var chain→DANGEROUS_SINK)
- [x] BasicBlock node'ları (CFG — if/else, while/for, return desteği)
- [x] BRANCHES_TO edge'leri

### Adım 12: Ek Clang özellikleri — DONE
- [x] Macro expansion — EXPANDS_MACRO edge'leri (MACRO_INSTANTIATION tracking)
- [x] Type resolution — typedef zinciri çözümleme (resolved_type property)
- [ ] Template instantiation — C++ template gerçek tipleri (deferred — Faz 3 kapsamına alındı)
- [x] Pointer analysis — void* cast (has_void_cast), pointer arithmetic (has_pointer_arith) flag'leri

### Adım 13: Clang testleri — DONE
- [x] CFG testleri (basic, if, loop, contains, multiple functions)
- [x] Data flow testleri (simple flow, independent vars)
- [x] Taint testleri (recv→memcpy chain, no taint without source)
- [x] Macro expansion testi
- [x] Typedef resolution testi
- [x] Pointer analysis testleri (void cast, pointer arith)
- [x] Edge case testleri (empty dir, non-C ignored, syntax error tolerance)
- [x] Builder entegrasyon testi (pipeline with clang)
- [x] Toplam: 62/62 test geçiyor (eski 44 + yeni 18)

---

## Faz 3: Tree-Sitter Deep Analysis (Rust, Java, Go, Kotlin, Swift) — DONE

### Adım 14: Tree-sitter deep analysis engine — DONE
- [x] `deep/lang_spec.py` — LangSpec frozen dataclass + REGISTRY
- [x] `deep/engine.py` — CFG builder, var def extraction, reaching definitions, data flow, taint
- [x] Statement wrapper unwrapping (expression_statement → if_expression etc.)
- [x] Ortak algoritmalar clang.py'den port (dil-bağımsız)

### Adım 15: Dil spesifikasyonları + pattern detector'lar — DONE
- [x] `deep/rust.py` — unsafe block, transmute, unwrap, raw deref pattern tespiti
- [x] `deep/java.py` — reflection, serialization, synchronized, native pattern tespiti
- [x] `deep/kotlin.py` — coroutine, force unwrap (!!), safe call (?.) pattern tespiti
- [x] `deep/go.py` — goroutine, defer, channel op, unsafe pointer, error check pattern tespiti
- [x] `deep/swift.py` — force unwrap, optional chain, force try, weak ref pattern tespiti
- [x] Kotlin/Swift opsiyonel — grammar yoksa skip

### Adım 16: Pipeline entegrasyonu — DONE
- [x] `deep/__init__.py` — TreeSitterDeepExtractor class (BaseExtractor)
- [x] `config.py` — `include_deep: bool = False` field
- [x] `builder.py` — Step 7/8: TreeSitterDeepExtractor (lazy import)
- [x] `cli.py` — `--include-deep/--no-deep` option
- [x] `archgraph_tool.py` — `find_unsafe_functions()`, `find_goroutine_spawners()`
- [x] `graph/__init__.py` — Lazy import ile circular dependency fix

### Adım 17: Testler — DONE
- [x] Rust CFG testleri (basic, if, loop) — 3 test
- [x] Rust data flow testleri (simple flow, independent) — 2 test
- [x] Rust taint testleri (chain, no taint) — 2 test
- [x] Rust pattern testleri (unsafe, transmute, unwrap) — 3 test
- [x] Java CFG testleri (basic, if) — 2 test
- [x] Java pattern testleri (reflection, synchronized) — 2 test
- [x] Go CFG testleri (basic, for loop) — 2 test
- [x] Go pattern testleri (goroutine, channel, defer) — 3 test
- [x] Kotlin pattern testleri (coroutine, force unwrap) — 2 test (skipif)
- [x] Swift pattern testleri (force unwrap, optional chain) — 2 test (skipif)
- [x] Edge case testleri (empty dir, unsupported lang, syntax error) — 3 test
- [x] Extractor integration testleri (Rust, Java, Go full extract, available_languages) — 4 test
- [x] Builder integration testi (pipeline with deep) — 1 test
- [x] Toplam: 93 test (89 passed + 4 skipped)

---

## Gelecek İyileştirmeler — DEFERRED

### CVE Enrichment
- [ ] Dependency→CVE eşleştirme (NVD/OSV API)
- [ ] API rate limit yönetimi
- [ ] CVE node tipi ve AFFECTED_BY edge'i

### Performans
- [ ] Paralel file parse (multiprocessing/asyncio)
- [ ] Incremental extraction (sadece değişen dosyalar)
- [ ] Neo4j APOC batch import kullanımı

### Ölçek Doğrulama
- [ ] Küçük proje testi (zlib ~50K LOC)
- [ ] Orta proje testi (OpenSSL ~500K LOC)
- [ ] Büyük proje testi (FFmpeg ~1M LOC)
- [ ] Extraction süresi ve graph boyutu benchmarkları

### rlm-agent İleri Entegrasyon
- [ ] Entry point kaydı ve auto-discovery
- [ ] Önceden tanımlı Cypher sorgu şablonları
- [ ] Graph diff (iki versiyon arası fark)
