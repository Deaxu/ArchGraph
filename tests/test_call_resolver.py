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
