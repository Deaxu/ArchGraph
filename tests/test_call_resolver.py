"""Tests for scope-aware call resolution."""

import textwrap
from pathlib import Path

import pytest

from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import GraphData, Node, NodeLabel, EdgeType


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
