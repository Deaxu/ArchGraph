"""Tests for tree-sitter deep analysis (Faz 3).

Tests CFG construction, data flow, taint tracking, and language-specific
pattern detection for Rust, Java, Go, Kotlin, and Swift.
"""

import importlib
import textwrap

import pytest
import tree_sitter as ts

from archgraph.extractors.deep.engine import (
    BasicBlock,
    FunctionAnalysis,
    VarDef,
    analyze_function,
    build_cfg,
    compute_reaching_definitions,
    emit_cfg_to_graph,
    extract_params,
    extract_var_defs,
    generate_data_flow_edges,
    propagate_taint,
)
from archgraph.extractors.deep.lang_spec import REGISTRY
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel


# ── Helpers ──────────────────────────────────────────────────────────────────


def _try_import_lang(lang: str):
    """Try to import a tree-sitter grammar, skip test if unavailable."""
    spec = REGISTRY.get(lang)
    if spec is None:
        pytest.skip(f"No spec registered for {lang}")
    try:
        mod = importlib.import_module(spec.ts_module)
        ts_lang = ts.Language(mod.language())
        parser = ts.Parser(ts_lang)
        return parser, spec
    except (ImportError, Exception):
        pytest.skip(f"tree-sitter grammar for {lang} not installed")


def _parse_and_find_func(parser, spec, source_text: str):
    """Parse source and return the first function node."""
    source = source_text.encode("utf-8")
    tree = parser.parse(source)
    root = tree.root_node

    def _find(node):
        if node.type in spec.function_def:
            return node
        for child in node.children:
            result = _find(child)
            if result is not None:
                return result
        return None

    func_node = _find(root)
    return func_node, source


# ══════════════════════════════════════════════════════════════════════════════
# Rust Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDeepRustCFG:
    """CFG construction tests for Rust."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("rust")

    def test_basic_cfg(self):
        """Simple function should produce a single basic block."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn add(a: i32, b: i32) -> i32 {
                let c = a + b;
                c
            }
        """))
        assert func is not None
        body = func.child_by_field_name("body")
        blocks = build_cfg(body, self.spec)
        assert len(blocks) >= 1
        # Entry block should have statements
        assert len(blocks[0].stmts) >= 1

    def test_if_cfg(self):
        """If expression should create then/join blocks."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn check(x: i32) -> i32 {
                if x > 0 {
                    return 1;
                }
                0
            }
        """))
        assert func is not None
        body = func.child_by_field_name("body")
        blocks = build_cfg(body, self.spec)
        # Should have at least: entry, then, join
        assert len(blocks) >= 3

    def test_loop_cfg(self):
        """While loop should create header/body/exit blocks."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn loop_fn(mut x: i32) -> i32 {
                while x > 0 {
                    x = x - 1;
                }
                x
            }
        """))
        assert func is not None
        body = func.child_by_field_name("body")
        blocks = build_cfg(body, self.spec)
        # Should have: entry, header, body, exit (at least 4)
        assert len(blocks) >= 4
        # Check back edge exists (body -> header)
        has_back_edge = False
        for b in blocks:
            for succ in b.successors:
                if succ < b.index:
                    has_back_edge = True
        assert has_back_edge, "Loop should have a back edge"


class TestDeepRustDataFlow:
    """Data flow tests for Rust."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("rust")

    def test_simple_flow(self):
        """Variable assignment chain should produce DATA_FLOWS_TO edges."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn flow() {
                let a = 1;
                let b = a;
                let c = b;
            }
        """))
        assert func is not None
        graph = GraphData()
        analysis = analyze_function(func, self.spec, src, "test.rs", graph)
        assert analysis is not None

        flow_edges = [e for e in graph.edges if e.type == EdgeType.DATA_FLOWS_TO]
        # a -> b and b -> c
        flow_vars = [(e.properties.get("from_var"), e.properties.get("to_var")) for e in flow_edges]
        assert ("a", "b") in flow_vars
        assert ("b", "c") in flow_vars

    def test_no_flow_independent(self):
        """Independent variables should not produce flow edges between them."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn independent() {
                let a = 1;
                let b = 2;
            }
        """))
        assert func is not None
        graph = GraphData()
        analyze_function(func, self.spec, src, "test.rs", graph)

        flow_edges = [e for e in graph.edges if e.type == EdgeType.DATA_FLOWS_TO]
        # No flow between a and b
        for e in flow_edges:
            pair = (e.properties.get("from_var"), e.properties.get("to_var"))
            assert pair != ("a", "b")
            assert pair != ("b", "a")


class TestDeepRustTaint:
    """Taint tracking tests for Rust."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("rust")

    def test_taint_chain(self):
        """Taint should propagate from read_to_string through to transmute."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn tainted(input: &str) {
                let data = read_to_string(input);
                let result = transmute(data);
            }
        """))
        assert func is not None
        graph = GraphData()
        analyze_function(func, self.spec, src, "test.rs", graph)

        taint_edges = [e for e in graph.edges if e.type == EdgeType.TAINTS]
        assert len(taint_edges) >= 1
        # Source should be read_to_string, sink should be transmute
        sources = {e.source_id for e in taint_edges}
        sinks = {e.target_id for e in taint_edges}
        assert any("read_to_string" in s for s in sources)
        assert any("transmute" in s for s in sinks)

    def test_no_taint_safe(self):
        """No taint edges when there's no input source."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn safe() {
                let a = 42;
                let b = a + 1;
            }
        """))
        assert func is not None
        graph = GraphData()
        analyze_function(func, self.spec, src, "test.rs", graph)

        taint_edges = [e for e in graph.edges if e.type == EdgeType.TAINTS]
        assert len(taint_edges) == 0


class TestDeepRustPatterns:
    """Rust-specific pattern detection tests."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("rust")

    def test_unsafe_block(self):
        """Should detect unsafe block inside a function."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn dangerous() {
                unsafe {
                    let ptr = std::ptr::null::<i32>();
                }
            }
        """))
        assert func is not None
        from archgraph.extractors.deep.rust import detect_rust_patterns
        flags = detect_rust_patterns(func, src)
        assert flags.get("has_unsafe_block") is True

    def test_transmute(self):
        """Should detect transmute usage."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn cast() {
                let x: u32 = unsafe { std::mem::transmute(1.0f32) };
            }
        """))
        assert func is not None
        from archgraph.extractors.deep.rust import detect_rust_patterns
        flags = detect_rust_patterns(func, src)
        assert flags.get("has_transmute") is True

    def test_unwrap(self):
        """Should detect .unwrap() usage."""
        func, src = _parse_and_find_func(self.parser, self.spec, textwrap.dedent("""\
            fn risky() {
                let val = Some(42).unwrap();
            }
        """))
        assert func is not None
        from archgraph.extractors.deep.rust import detect_rust_patterns
        flags = detect_rust_patterns(func, src)
        assert flags.get("has_unwrap") is True


# ══════════════════════════════════════════════════════════════════════════════
# Java Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDeepJavaCFG:
    """CFG construction tests for Java."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("java")

    def test_basic_cfg(self):
        """Simple method should produce at least one basic block."""
        source = textwrap.dedent("""\
            class Foo {
                int add(int a, int b) {
                    int c = a + b;
                    return c;
                }
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        body = func.child_by_field_name("body")
        assert body is not None
        blocks = build_cfg(body, self.spec)
        assert len(blocks) >= 1

    def test_if_cfg(self):
        """If statement should create branching blocks."""
        source = textwrap.dedent("""\
            class Foo {
                int check(int x) {
                    if (x > 0) {
                        return 1;
                    }
                    return 0;
                }
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        body = func.child_by_field_name("body")
        blocks = build_cfg(body, self.spec)
        assert len(blocks) >= 3


class TestDeepJavaPatterns:
    """Java-specific pattern detection tests."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("java")

    def test_reflection(self):
        """Should detect reflection usage."""
        source = textwrap.dedent("""\
            class Foo {
                void reflect() throws Exception {
                    Class cls = Class.forName("Bar");
                    Object obj = cls.getDeclaredMethod("test").invoke(null);
                }
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        from archgraph.extractors.deep.java import detect_java_patterns
        flags = detect_java_patterns(func, src)
        assert flags.get("has_reflection") is True

    def test_synchronized(self):
        """Should detect synchronized usage."""
        source = textwrap.dedent("""\
            class Foo {
                synchronized void locked() {
                    int x = 1;
                }
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        from archgraph.extractors.deep.java import detect_java_patterns
        flags = detect_java_patterns(func, src)
        assert flags.get("has_synchronized") is True


# ══════════════════════════════════════════════════════════════════════════════
# Go Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDeepGoCFG:
    """CFG construction tests for Go."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("go")

    def test_basic_cfg(self):
        """Simple function should produce basic blocks."""
        source = textwrap.dedent("""\
            package main

            func add(a int, b int) int {
                c := a + b
                return c
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        body = func.child_by_field_name("body")
        assert body is not None
        blocks = build_cfg(body, self.spec)
        assert len(blocks) >= 1

    def test_for_loop(self):
        """For loop should create header/body/exit blocks."""
        source = textwrap.dedent("""\
            package main

            func loop(n int) int {
                sum := 0
                for i := 0; i < n; i++ {
                    sum = sum + i
                }
                return sum
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        body = func.child_by_field_name("body")
        blocks = build_cfg(body, self.spec)
        assert len(blocks) >= 4  # entry, header, body, exit


class TestDeepGoPatterns:
    """Go-specific pattern detection tests."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("go")

    def test_goroutine(self):
        """Should detect goroutine spawning."""
        source = textwrap.dedent("""\
            package main

            func spawn() {
                go func() {
                    println("hello")
                }()
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        from archgraph.extractors.deep.go import detect_go_patterns
        flags = detect_go_patterns(func, src)
        assert flags.get("has_goroutine") is True

    def test_channel(self):
        """Should detect channel operations."""
        source = textwrap.dedent("""\
            package main

            func send(ch chan int) {
                ch <- 42
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        from archgraph.extractors.deep.go import detect_go_patterns
        flags = detect_go_patterns(func, src)
        assert flags.get("has_channel_op") is True

    def test_defer(self):
        """Should detect defer usage."""
        source = textwrap.dedent("""\
            package main

            func cleanup() {
                defer close()
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        assert func is not None
        from archgraph.extractors.deep.go import detect_go_patterns
        flags = detect_go_patterns(func, src)
        assert flags.get("has_defer") is True


# ══════════════════════════════════════════════════════════════════════════════
# Kotlin Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDeepKotlinPatterns:
    """Kotlin-specific pattern detection tests (skipped if grammar not installed)."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("kotlin")

    def test_coroutine(self):
        """Should detect coroutine usage."""
        source = textwrap.dedent("""\
            suspend fun fetchData() {
                val result = withContext(Dispatchers.IO) { load() }
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        if func is None:
            pytest.skip("Kotlin parser couldn't find function")
        from archgraph.extractors.deep.kotlin import detect_kotlin_patterns
        flags = detect_kotlin_patterns(func, src)
        assert flags.get("has_coroutine") is True

    def test_force_unwrap(self):
        """Should detect !! operator."""
        source = textwrap.dedent("""\
            fun risky(x: String?) {
                val len = x!!.length
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        if func is None:
            pytest.skip("Kotlin parser couldn't find function")
        from archgraph.extractors.deep.kotlin import detect_kotlin_patterns
        flags = detect_kotlin_patterns(func, src)
        assert flags.get("has_force_unwrap") is True


# ══════════════════════════════════════════════════════════════════════════════
# Swift Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDeepSwiftPatterns:
    """Swift-specific pattern detection tests (skipped if grammar not installed)."""

    def setup_method(self):
        self.parser, self.spec = _try_import_lang("swift")

    def test_force_unwrap(self):
        """Should detect force unwrap (!)."""
        source = textwrap.dedent("""\
            func risky(x: String?) -> Int {
                return x!.count
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        if func is None:
            pytest.skip("Swift parser couldn't find function")
        from archgraph.extractors.deep.swift import detect_swift_patterns
        flags = detect_swift_patterns(func, src)
        assert flags.get("has_force_unwrap") is True

    def test_optional_chain(self):
        """Should detect optional chaining (?.)."""
        source = textwrap.dedent("""\
            func safe(x: String?) -> Int? {
                return x?.count
            }
        """)
        func, src = _parse_and_find_func(self.parser, self.spec, source)
        if func is None:
            pytest.skip("Swift parser couldn't find function")
        from archgraph.extractors.deep.swift import detect_swift_patterns
        flags = detect_swift_patterns(func, src)
        assert flags.get("has_optional_chain") is True


# ══════════════════════════════════════════════════════════════════════════════
# Edge Cases
# ══════════════════════════════════════════════════════════════════════════════


class TestDeepEdgeCases:
    """Edge case tests for deep analysis."""

    def test_empty_dir(self, tmp_path):
        """Empty directory should return empty graph."""
        from archgraph.extractors.deep import TreeSitterDeepExtractor
        ext = TreeSitterDeepExtractor()
        graph = ext.extract(tmp_path)
        assert graph.node_count == 0
        assert graph.edge_count == 0

    def test_unsupported_lang(self, tmp_path):
        """Files with unsupported extensions should be ignored."""
        (tmp_path / "test.py").write_text("def foo(): pass\n")
        from archgraph.extractors.deep import TreeSitterDeepExtractor
        ext = TreeSitterDeepExtractor()
        graph = ext.extract(tmp_path)
        assert graph.node_count == 0

    def test_syntax_error_tolerance(self, tmp_path):
        """Syntax errors should not crash the extractor."""
        parser, spec = _try_import_lang("rust")
        (tmp_path / "bad.rs").write_text("fn broken( { let x = ; }\n")
        from archgraph.extractors.deep import TreeSitterDeepExtractor
        ext = TreeSitterDeepExtractor(languages=["rust"])
        graph = ext.extract(tmp_path)
        # Should not crash — may produce partial results or empty
        assert isinstance(graph, GraphData)


# ══════════════════════════════════════════════════════════════════════════════
# Extractor Integration Tests
# ══════════════════════════════════════════════════════════════════════════════


class TestDeepExtractorIntegration:
    """Integration tests using TreeSitterDeepExtractor on real files."""

    def test_rust_full_extract(self, tmp_path):
        """Full extraction on a Rust file should produce CFG + data flow."""
        _try_import_lang("rust")

        (tmp_path / "lib.rs").write_text(textwrap.dedent("""\
            fn process(input: &str) -> i32 {
                let x = 1;
                let y = x + 2;
                if y > 0 {
                    return y;
                }
                0
            }
        """))

        from archgraph.extractors.deep import TreeSitterDeepExtractor
        ext = TreeSitterDeepExtractor(languages=["rust"])
        graph = ext.extract(tmp_path)

        # Should have BasicBlock nodes
        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        assert len(bb_nodes) >= 3, f"Expected >= 3 BasicBlocks, got {len(bb_nodes)}"

        # Should have BRANCHES_TO edges
        branches = [e for e in graph.edges if e.type == EdgeType.BRANCHES_TO]
        assert len(branches) >= 1

        # Should have CONTAINS edges for BBs
        bb_contains = [
            e for e in graph.edges
            if e.type == EdgeType.CONTAINS and e.target_id.startswith("bb:")
        ]
        assert len(bb_contains) >= 1

        # Should have DATA_FLOWS_TO (x -> y)
        flows = [e for e in graph.edges if e.type == EdgeType.DATA_FLOWS_TO]
        assert len(flows) >= 1

    def test_java_full_extract(self, tmp_path):
        """Full extraction on a Java file."""
        _try_import_lang("java")

        (tmp_path / "Main.java").write_text(textwrap.dedent("""\
            class Main {
                int compute(int a, int b) {
                    int sum = a + b;
                    return sum;
                }
            }
        """))

        from archgraph.extractors.deep import TreeSitterDeepExtractor
        ext = TreeSitterDeepExtractor(languages=["java"])
        graph = ext.extract(tmp_path)

        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        assert len(bb_nodes) >= 1

    def test_go_full_extract(self, tmp_path):
        """Full extraction on a Go file."""
        _try_import_lang("go")

        (tmp_path / "main.go").write_text(textwrap.dedent("""\
            package main

            func compute(a int, b int) int {
                sum := a + b
                return sum
            }
        """))

        from archgraph.extractors.deep import TreeSitterDeepExtractor
        ext = TreeSitterDeepExtractor(languages=["go"])
        graph = ext.extract(tmp_path)

        bb_nodes = [n for n in graph.nodes if n.label == NodeLabel.BASIC_BLOCK]
        assert len(bb_nodes) >= 1

    def test_available_languages(self):
        """available_languages should return only loaded languages."""
        from archgraph.extractors.deep import TreeSitterDeepExtractor
        ext = TreeSitterDeepExtractor()
        langs = ext.available_languages
        # Rust, Java, Go should always be available (core deps)
        assert "rust" in langs
        assert "java" in langs
        assert "go" in langs
