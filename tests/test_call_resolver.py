"""Tests for scope-aware call resolution."""

import textwrap
from pathlib import Path

import pytest

from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import GraphData, Node, NodeLabel, EdgeType

pytestmark = pytest.mark.call_resolution


def _ts_lang_available(lang: str) -> bool:
    try:
        ext = TreeSitterExtractor(languages=[lang])
        return lang in ext._parsers
    except Exception:
        return False


# ── Task 1: Qualifier Extraction ─────────────────────────────────────────────


class TestQualifierExtraction:
    """Test _get_callee_name returns (name, qualifier) tuple."""

    @pytest.mark.skipif(not _ts_lang_available("c"), reason="c grammar not installed")
    def test_simple_call_no_qualifier(self, tmp_path):
        """Plain function call -> qualifier is None."""
        src = tmp_path / "main.c"
        src.write_text(textwrap.dedent("""\
            void caller(void) {
                foo();
            }
        """))
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_path)
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) >= 1
        call = calls[0]
        assert call.target_id == "funcref:foo"
        assert call.properties.get("qualifier") is None

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_method_call_with_qualifier(self, tmp_path):
        """obj.method() -> qualifier is 'obj'."""
        src = tmp_path / "main.ts"
        src.write_text(textwrap.dedent("""\
            function caller() {
                Counter.increment();
            }
        """))
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) >= 1
        call = calls[0]
        assert call.target_id == "funcref:Counter.increment"
        assert call.properties.get("qualifier") == "Counter"

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_this_self_super_skipped(self, tmp_path):
        """this.method() -> qualifier is None (this/self/super are skipped)."""
        src = tmp_path / "main.ts"
        src.write_text(textwrap.dedent("""\
            function caller() {
                this.doSomething();
            }
        """))
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) >= 1
        call = calls[0]
        assert call.target_id == "funcref:doSomething"
        assert call.properties.get("qualifier") is None

    @pytest.mark.skipif(not _ts_lang_available("c"), reason="c grammar not installed")
    def test_arrow_call_qualifier(self, tmp_path):
        """ptr->method() -> qualifier is 'ptr'."""
        src = tmp_path / "main.c"
        src.write_text(textwrap.dedent("""\
            void caller(void) {
                obj->process();
            }
        """))
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_path)
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert len(calls) >= 1
        call = calls[0]
        assert call.target_id == "funcref:obj.process"
        assert call.properties.get("qualifier") == "obj"


# ── Task 2: Named Import Parsing ─────────────────────────────────────────────


class TestNamedImportParsing:
    """Test that IMPORTS edges get a 'names' property with imported symbols."""

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_js_named_import(self, tmp_path):
        src = tmp_path / "main.ts"
        src.write_text('import { foo, bar } from "./utils";\n')
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "foo,bar"

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_js_default_import(self, tmp_path):
        src = tmp_path / "main.ts"
        src.write_text('import Foo from "./utils";\n')
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "Foo"

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_js_wildcard_import_skipped(self, tmp_path):
        src = tmp_path / "main.ts"
        src.write_text('import * as utils from "./utils";\n')
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == ""

    @pytest.mark.skipif(
        not _ts_lang_available("typescript"), reason="typescript grammar not installed"
    )
    def test_js_alias_import(self, tmp_path):
        src = tmp_path / "main.ts"
        src.write_text('import { foo as f } from "./utils";\n')
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "f"

    @pytest.mark.skipif(not _ts_lang_available("rust"), reason="rust grammar not installed")
    def test_rust_use_import(self, tmp_path):
        src = tmp_path / "main.rs"
        src.write_text("use crate::utils::foo;\n")
        ext = TreeSitterExtractor(languages=["rust"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "foo"

    @pytest.mark.skipif(not _ts_lang_available("java"), reason="java grammar not installed")
    def test_java_import(self, tmp_path):
        src = tmp_path / "Foo.java"
        src.write_text("import com.example.Foo;\n")
        ext = TreeSitterExtractor(languages=["java"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "Foo"

    @pytest.mark.skipif(not _ts_lang_available("go"), reason="go grammar not installed")
    def test_go_import(self, tmp_path):
        src = tmp_path / "main.go"
        src.write_text('package main\n\nimport "fmt"\n')
        ext = TreeSitterExtractor(languages=["go"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == "fmt"

    @pytest.mark.skipif(not _ts_lang_available("c"), reason="c grammar not installed")
    def test_c_include_no_names(self, tmp_path):
        src = tmp_path / "main.c"
        src.write_text('#include "utils.h"\n')
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_path)
        imports = [e for e in graph.edges if e.type == EdgeType.IMPORTS]
        assert len(imports) >= 1
        imp = imports[0]
        assert imp.properties.get("names") == ""


# ── Tasks 3-6: CallResolver ──────────────────────────────────────────────────

from archgraph.extractors.call_resolver import CallResolver


class TestSymbolTable:
    def test_file_funcs_index(self):
        graph = GraphData()
        graph.add_node("func:src/a.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/a.ts", line_start=1)
        graph.add_node("func:src/a.ts:bar:5", NodeLabel.FUNCTION, name="bar", file="src/a.ts", line_start=5)
        graph.add_node("func:src/b.ts:baz:1", NodeLabel.FUNCTION, name="baz", file="src/b.ts", line_start=1)
        resolver = CallResolver(graph)
        assert len(resolver._file_funcs["src/a.ts"]) == 2
        assert len(resolver._file_funcs["src/b.ts"]) == 1

    def test_name_to_defs_index(self):
        graph = GraphData()
        graph.add_node("func:src/a.ts:add:1", NodeLabel.FUNCTION, name="add", file="src/a.ts", line_start=1)
        graph.add_node("func:src/b.ts:add:3", NodeLabel.FUNCTION, name="add", file="src/b.ts", line_start=3)
        graph.add_node("func:src/c.ts:unique:1", NodeLabel.FUNCTION, name="unique", file="src/c.ts", line_start=1)
        resolver = CallResolver(graph)
        assert len(resolver._name_to_defs["add"]) == 2
        assert len(resolver._name_to_defs["unique"]) == 1

    def test_qualified_index_from_contains(self):
        graph = GraphData()
        graph.add_node("class:src/a.ts:Counter:1", NodeLabel.CLASS, name="Counter", file="src/a.ts")
        graph.add_node("func:src/a.ts:increment:3", NodeLabel.FUNCTION, name="increment", file="src/a.ts", line_start=3)
        graph.add_edge("class:src/a.ts:Counter:1", "func:src/a.ts:increment:3", EdgeType.CONTAINS)
        resolver = CallResolver(graph)
        assert "Counter.increment" in resolver._qualified_to_def

    def test_import_map_from_edges(self):
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("module:./utils", NodeLabel.MODULE, name="./utils")
        graph.add_edge("file:src/app.ts", "module:./utils", EdgeType.IMPORTS, names="foo,bar", raw='x')
        resolver = CallResolver(graph)
        assert resolver._import_map[("src/app.ts", "foo")] == "./utils"
        assert resolver._import_map[("src/app.ts", "bar")] == "./utils"

    def test_file_set_from_file_nodes(self):
        graph = GraphData()
        graph.add_node("file:src/a.ts", NodeLabel.FILE, path="src/a.ts")
        graph.add_node("file:src/b.ts", NodeLabel.FILE, path="src/b.ts")
        resolver = CallResolver(graph)
        assert "src/a.ts" in resolver._file_set
        assert "src/b.ts" in resolver._file_set

    def test_funcref_excluded(self):
        graph = GraphData()
        graph.add_node("func:src/a.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/a.ts", line_start=1)
        graph.add_node("funcref:bar", NodeLabel.FUNCTION, name="bar")
        resolver = CallResolver(graph)
        assert "foo" in resolver._name_to_defs
        assert "bar" not in resolver._name_to_defs


class TestModulePathResolve:
    def test_relative_ts(self):
        graph = GraphData()
        graph.add_node("file:src/utils.ts", NodeLabel.FILE, path="src/utils.ts")
        resolver = CallResolver(graph)
        assert resolver._resolve_module_path("src/app.ts", "./utils") == "src/utils.ts"

    def test_index_fallback(self):
        graph = GraphData()
        graph.add_node("file:src/utils/index.ts", NodeLabel.FILE, path="src/utils/index.ts")
        resolver = CallResolver(graph)
        assert resolver._resolve_module_path("src/app.ts", "./utils") == "src/utils/index.ts"

    def test_parent_dir(self):
        graph = GraphData()
        graph.add_node("file:src/helpers.ts", NodeLabel.FILE, path="src/helpers.ts")
        resolver = CallResolver(graph)
        assert resolver._resolve_module_path("src/components/App.ts", "../helpers") == "src/helpers.ts"

    def test_java_package(self):
        graph = GraphData()
        graph.add_node("file:com/example/utils/Foo.java", NodeLabel.FILE, path="com/example/utils/Foo.java")
        resolver = CallResolver(graph)
        assert resolver._resolve_module_path("src/Main.java", "com.example.utils.Foo") == "com/example/utils/Foo.java"

    def test_rust_crate(self):
        graph = GraphData()
        graph.add_node("file:src/utils.rs", NodeLabel.FILE, path="src/utils.rs")
        resolver = CallResolver(graph)
        assert resolver._resolve_module_path("src/main.rs", "crate::utils") == "src/utils.rs"

    def test_external_none(self):
        graph = GraphData()
        resolver = CallResolver(graph)
        assert resolver._resolve_module_path("src/app.ts", "react") is None

    def test_backslash(self):
        graph = GraphData()
        graph.add_node("file:src\\utils.ts", NodeLabel.FILE, path="src\\utils.ts")
        resolver = CallResolver(graph)
        assert resolver._resolve_module_path("src\\app.ts", "./utils") is not None


class TestQualifierMatch:
    def test_qualified_resolves(self):
        graph = GraphData()
        graph.add_node("class:src/a.ts:Counter:1", NodeLabel.CLASS, name="Counter", file="src/a.ts")
        graph.add_node("func:src/a.ts:increment:3", NodeLabel.FUNCTION, name="increment", file="src/a.ts", line_start=3)
        graph.add_edge("class:src/a.ts:Counter:1", "func:src/a.ts:increment:3", EdgeType.CONTAINS)
        graph.add_node("func:src/b.ts:main:1", NodeLabel.FUNCTION, name="main", file="src/b.ts", line_start=1)
        graph.add_node("funcref:Counter.increment", NodeLabel.FUNCTION, name="increment")
        graph.add_edge("func:src/b.ts:main:1", "funcref:Counter.increment", EdgeType.CALLS, qualifier="Counter")
        CallResolver(graph).resolve()
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert calls[0].target_id == "func:src/a.ts:increment:3"
        assert calls[0].properties.get("resolved") is True
        assert not any(n.id == "funcref:Counter.increment" for n in graph.nodes)


class TestIntraFileMatch:
    def test_same_file_resolves(self):
        graph = GraphData()
        graph.add_node("func:src/a.ts:helper:1", NodeLabel.FUNCTION, name="helper", file="src/a.ts", line_start=1)
        graph.add_node("func:src/a.ts:main:10", NodeLabel.FUNCTION, name="main", file="src/a.ts", line_start=10)
        graph.add_node("funcref:helper", NodeLabel.FUNCTION, name="helper")
        graph.add_edge("func:src/a.ts:main:10", "funcref:helper", EdgeType.CALLS)
        CallResolver(graph).resolve()
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert calls[0].target_id == "func:src/a.ts:helper:1"

    def test_line_proximity(self):
        graph = GraphData()
        graph.add_node("func:src/a.ts:helper:1", NodeLabel.FUNCTION, name="helper", file="src/a.ts", line_start=1)
        graph.add_node("func:src/a.ts:helper:50", NodeLabel.FUNCTION, name="helper", file="src/a.ts", line_start=50)
        graph.add_node("func:src/a.ts:caller:45", NodeLabel.FUNCTION, name="caller", file="src/a.ts", line_start=45)
        graph.add_node("funcref:helper", NodeLabel.FUNCTION, name="helper")
        graph.add_edge("func:src/a.ts:caller:45", "funcref:helper", EdgeType.CALLS)
        CallResolver(graph).resolve()
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert calls[0].target_id == "func:src/a.ts:helper:50"


class TestImportMatch:
    def test_import_resolves(self):
        graph = GraphData()
        graph.add_node("file:src/app.ts", NodeLabel.FILE, path="src/app.ts")
        graph.add_node("file:src/utils.ts", NodeLabel.FILE, path="src/utils.ts")
        graph.add_node("module:./utils", NodeLabel.MODULE, name="./utils")
        graph.add_edge("file:src/app.ts", "module:./utils", EdgeType.IMPORTS, names="foo", raw='x')
        graph.add_node("func:src/utils.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/utils.ts", line_start=1)
        graph.add_node("func:src/app.ts:main:1", NodeLabel.FUNCTION, name="main", file="src/app.ts", line_start=1)
        graph.add_node("funcref:foo", NodeLabel.FUNCTION, name="foo")
        graph.add_edge("func:src/app.ts:main:1", "funcref:foo", EdgeType.CALLS)
        CallResolver(graph).resolve()
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert calls[0].target_id == "func:src/utils.ts:foo:1"


class TestGlobalUnique:
    def test_unique_resolves(self):
        graph = GraphData()
        graph.add_node("func:src/b.ts:uniqueFunc:1", NodeLabel.FUNCTION, name="uniqueFunc", file="src/b.ts", line_start=1)
        graph.add_node("func:src/a.ts:caller:1", NodeLabel.FUNCTION, name="caller", file="src/a.ts", line_start=1)
        graph.add_node("funcref:uniqueFunc", NodeLabel.FUNCTION, name="uniqueFunc")
        graph.add_edge("func:src/a.ts:caller:1", "funcref:uniqueFunc", EdgeType.CALLS)
        CallResolver(graph).resolve()
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert calls[0].target_id == "func:src/b.ts:uniqueFunc:1"

    def test_ambiguous_stays(self):
        graph = GraphData()
        graph.add_node("func:src/b.ts:add:1", NodeLabel.FUNCTION, name="add", file="src/b.ts", line_start=1)
        graph.add_node("func:src/c.ts:add:1", NodeLabel.FUNCTION, name="add", file="src/c.ts", line_start=1)
        graph.add_node("func:src/a.ts:caller:1", NodeLabel.FUNCTION, name="caller", file="src/a.ts", line_start=1)
        graph.add_node("funcref:add", NodeLabel.FUNCTION, name="add")
        graph.add_edge("func:src/a.ts:caller:1", "funcref:add", EdgeType.CALLS)
        CallResolver(graph).resolve()
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert calls[0].target_id == "funcref:add"


class TestUnresolvedRemain:
    def test_external_stays(self):
        graph = GraphData()
        graph.add_node("func:src/a.ts:main:1", NodeLabel.FUNCTION, name="main", file="src/a.ts", line_start=1)
        graph.add_node("funcref:console.log", NodeLabel.FUNCTION, name="log")
        graph.add_edge("func:src/a.ts:main:1", "funcref:console.log", EdgeType.CALLS, qualifier="console")
        CallResolver(graph).resolve()
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS]
        assert calls[0].target_id == "funcref:console.log"
        assert any(n.id == "funcref:console.log" for n in graph.nodes)


class TestResolutionStats:
    def test_stats_logged(self, caplog):
        import logging
        graph = GraphData()
        graph.add_node("func:src/a.ts:foo:1", NodeLabel.FUNCTION, name="foo", file="src/a.ts", line_start=1)
        graph.add_node("func:src/a.ts:caller:10", NodeLabel.FUNCTION, name="caller", file="src/a.ts", line_start=10)
        graph.add_node("funcref:foo", NodeLabel.FUNCTION, name="foo")
        graph.add_edge("func:src/a.ts:caller:10", "funcref:foo", EdgeType.CALLS)
        graph.add_node("funcref:externalFunc", NodeLabel.FUNCTION, name="externalFunc")
        graph.add_edge("func:src/a.ts:caller:10", "funcref:externalFunc", EdgeType.CALLS)
        with caplog.at_level(logging.INFO, logger="archgraph.extractors.call_resolver"):
            CallResolver(graph).resolve()
        assert "Resolved 1/2" in caplog.text
        assert "50.0%" in caplog.text


class TestIntegration:
    @pytest.mark.skipif(not _ts_lang_available("typescript"), reason="typescript grammar not installed")
    def test_multi_file_ts(self, tmp_path):
        (tmp_path / "utils.ts").write_text(textwrap.dedent("""\
            export function add(a: number, b: number): number {
                return a + b;
            }
        """))
        (tmp_path / "app.ts").write_text(textwrap.dedent("""\
            import { add } from "./utils";
            function main() {
                const result = add(1, 2);
            }
        """))
        ext = TreeSitterExtractor(languages=["typescript"], include_body=False)
        graph = ext.extract(tmp_path)
        graph.deduplicate()
        CallResolver(graph).resolve()
        calls_from_main = [e for e in graph.edges if e.type == EdgeType.CALLS and "main" in e.source_id]
        resolved = [e for e in calls_from_main if e.properties.get("resolved")]
        assert len(resolved) >= 1
        assert resolved[0].target_id.startswith("func:")

    @pytest.mark.skipif(not _ts_lang_available("c"), reason="c grammar not installed")
    def test_c_intra_file(self, tmp_path):
        (tmp_path / "main.c").write_text(textwrap.dedent("""\
            int helper(int x) { return x + 1; }
            int main(void) { int r = helper(42); return r; }
        """))
        ext = TreeSitterExtractor(languages=["c"], include_body=False)
        graph = ext.extract(tmp_path)
        graph.deduplicate()
        CallResolver(graph).resolve()
        calls = [e for e in graph.edges if e.type == EdgeType.CALLS and "main" in e.source_id]
        helper_calls = [e for e in calls if "helper" in e.target_id]
        assert len(helper_calls) >= 1
        assert helper_calls[0].target_id.startswith("func:")
        assert helper_calls[0].properties.get("resolved") is True
