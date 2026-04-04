"""Functional tests for archgraph.search.HybridSearcher.

Tests BM25 + graph-relevance hybrid search with mocked Neo4j store.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from archgraph.search import HybridSearcher

pytestmark = [pytest.mark.core]


class TestTokenizer:
    """Test BM25 tokenizer behavior."""

    def _tokenize(self, text: str) -> list[str]:
        """Helper: access tokenizer via a throwaway HybridSearcher."""
        store = MagicMock()
        searcher = HybridSearcher(store)
        return searcher._tokenize(text)

    def test_snake_case_splitting(self):
        """parse_data should split into [parse, data]."""
        tokens = self._tokenize("parse_data")
        assert "parse" in tokens
        assert "data" in tokens

    def test_single_word(self):
        """A single word should appear as-is."""
        tokens = self._tokenize("main")
        assert tokens == ["main"]

    def test_empty_string(self):
        """Empty string should return empty list."""
        tokens = self._tokenize("")
        assert tokens == []

    def test_path_separators_split(self):
        """Slashes and dots in paths should split into parts."""
        tokens = self._tokenize("src/utils/helper.ts")
        assert "src" in tokens
        assert "utils" in tokens
        assert "helper" in tokens
        assert "ts" in tokens

    def test_numeric_tokens_preserved(self):
        """Numbers in identifiers should be kept."""
        tokens = self._tokenize("sha256_hash")
        assert "sha256" in tokens
        assert "hash" in tokens

    def test_lowercased(self):
        """All tokens should be lowercased."""
        tokens = self._tokenize("MyClass")
        assert all(t == t.lower() for t in tokens)

    def test_camelcase_lowered_before_split(self):
        """The tokenizer lowercases text before regex extraction.

        camelCase splitting should work: 'parseData' should produce
        both the full token 'parsedata' AND the sub-parts 'parse', 'data'.
        """
        tokens = self._tokenize("parseData")
        assert "parsedata" in tokens
        assert "parse" in tokens
        assert "data" in tokens


class TestBM25Search:
    """Test BM25 scoring correctness."""

    def _make_searcher_with_data(
        self, nodes_data: list[dict],
    ) -> HybridSearcher:
        """Helper: Create searcher with mock store returning given nodes."""
        store = MagicMock()
        store.query.return_value = nodes_data
        searcher = HybridSearcher(store)
        searcher.build_index()
        return searcher

    # ------------------------------------------------------------------ #
    # Ranking tests
    # ------------------------------------------------------------------ #

    def test_exact_name_match_ranks_first(self):
        """Searching 'main' should rank func with name='main' above 'main_loop'."""
        nodes = [
            {
                "id": "func:a.c:main:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "main", "file": "a.c"},
            },
            {
                "id": "func:b.c:main_loop:5",
                "labels": ["Function", "_Node"],
                "props": {"name": "main_loop", "file": "b.c"},
            },
            {
                "id": "func:c.c:helper:10",
                "labels": ["Function", "_Node"],
                "props": {"name": "helper", "file": "c.c"},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("main")
        assert len(results) >= 2
        assert results[0]["name"] == "main"

    def test_no_results_for_nonexistent_term(self):
        """Searching for a term in no document should return empty or zero-score."""
        nodes = [
            {
                "id": "func:a.c:foo:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "foo", "file": "a.c"},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("zzzznonexistent")
        assert len(results) == 0 or all(r["score"] == 0 for r in results)

    def test_security_boost_input_source(self):
        """Input source functions should rank higher via graph relevance boost."""
        nodes = [
            {
                "id": "func:a.c:recv:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "recv_data", "file": "a.c", "is_input_source": True},
            },
            {
                "id": "func:b.c:recv:5",
                "labels": ["Function", "_Node"],
                "props": {"name": "recv_helper", "file": "b.c"},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("recv")
        assert len(results) == 2
        # The security-flagged one should score higher
        assert results[0]["id"] == "func:a.c:recv:1"

    # ------------------------------------------------------------------ #
    # Filtering tests
    # ------------------------------------------------------------------ #

    def test_label_filter_works(self):
        """label_filter='Function' should exclude Class nodes."""
        nodes = [
            {
                "id": "func:a.c:parse:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "parse", "file": "a.c"},
            },
            {
                "id": "class:b.java:Parser:1",
                "labels": ["Class", "_Node"],
                "props": {"name": "Parser", "file": "b.java"},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("parse", label_filter="Function")
        assert all("Function" in r["labels"] for r in results)
        assert all("Class" not in r["labels"] or "Function" in r["labels"] for r in results)

    def test_top_k_limits_results(self):
        """top_k=2 should return at most 2 results."""
        nodes = [
            {
                "id": f"func:a.c:func{i}:{i}",
                "labels": ["Function", "_Node"],
                "props": {"name": f"func{i}", "file": "a.c"},
            }
            for i in range(10)
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("func", top_k=2)
        assert len(results) <= 2

    # ------------------------------------------------------------------ #
    # Result structure tests
    # ------------------------------------------------------------------ #

    def test_result_structure(self):
        """Search results must have all required fields."""
        nodes = [
            {
                "id": "func:a.c:foo:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "foo", "file": "a.c"},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("foo")
        assert len(results) > 0
        r = results[0]
        assert "id" in r
        assert "score" in r
        assert "name" in r
        assert "file" in r
        assert "labels" in r
        assert "snippet" in r
        assert "security" in r
        assert isinstance(r["score"], float)

    def test_security_fields_in_result(self):
        """Result security dict should contain is_input_source and is_dangerous_sink."""
        nodes = [
            {
                "id": "func:a.c:foo:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "foo", "file": "a.c", "is_input_source": True},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("foo")
        assert len(results) > 0
        sec = results[0]["security"]
        assert "is_input_source" in sec
        assert "is_dangerous_sink" in sec
        assert sec["is_input_source"] is True
        assert sec["is_dangerous_sink"] is False

    def test_snippet_is_string(self):
        """Snippet should be a string, possibly containing matching text."""
        nodes = [
            {
                "id": "func:a.c:foo:1",
                "labels": ["Function", "_Node"],
                "props": {
                    "name": "process_authentication",
                    "file": "src/auth.c",
                    "body": "void process_authentication(char* token) { validate(token); }",
                },
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("authentication")
        assert len(results) > 0
        assert isinstance(results[0]["snippet"], str)

    # ------------------------------------------------------------------ #
    # Edge cases
    # ------------------------------------------------------------------ #

    def test_empty_index_returns_empty(self):
        """Search on empty index should return empty list, not crash."""
        store = MagicMock()
        store.query.return_value = []
        searcher = HybridSearcher(store)
        searcher.build_index()
        results = searcher.search("anything")
        assert results == []

    def test_empty_query_returns_empty(self):
        """Empty query string should return empty list."""
        nodes = [
            {
                "id": "func:a.c:foo:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "foo", "file": "a.c"},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("")
        assert results == []

    def test_score_normalization(self):
        """Scores should be between 0 and 1 (inclusive) after normalization."""
        nodes = [
            {
                "id": f"func:a.c:fn{i}:{i}",
                "labels": ["Function", "_Node"],
                "props": {"name": f"fn{i}", "file": "a.c"},
            }
            for i in range(5)
        ]
        # Add one with a matching name
        nodes.append({
            "id": "func:x.c:target:1",
            "labels": ["Function", "_Node"],
            "props": {"name": "target", "file": "x.c"},
        })
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("target")
        for r in results:
            assert 0 <= r["score"] <= 1.0001, f"Score {r['score']} out of range"

    def test_build_index_calls_store_query(self):
        """build_index should issue a Cypher query to load nodes."""
        store = MagicMock()
        store.query.return_value = []
        searcher = HybridSearcher(store)
        searcher.build_index()
        store.query.assert_called_once()
        cypher = store.query.call_args[0][0]
        assert "MATCH" in cypher
        assert "_Node" in cypher

    def test_bm25_weight_zero_uses_only_graph(self):
        """With bm25_weight=0, only graph relevance matters."""
        nodes = [
            {
                "id": "func:a.c:recv:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "recv", "file": "a.c", "is_input_source": True},
            },
            {
                "id": "func:b.c:send:5",
                "labels": ["Function", "_Node"],
                "props": {"name": "send", "file": "b.c"},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        # Both match 'recv' or 'send' via BM25 differently, but with bm25_weight=0
        # only graph_relevance should matter
        results = searcher.search("recv", bm25_weight=0.0, graph_weight=1.0)
        # recv has is_input_source boost, so it should rank first
        if len(results) >= 1:
            assert results[0]["id"] == "func:a.c:recv:1"

    def test_multiple_label_filter(self):
        """Class nodes should be excluded when filtering for Function."""
        nodes = [
            {
                "id": "func:a.py:parse:1",
                "labels": ["Function", "_Node"],
                "props": {"name": "parse", "file": "a.py"},
            },
            {
                "id": "class:a.py:Parser:1",
                "labels": ["Class", "_Node"],
                "props": {"name": "Parser", "file": "a.py"},
            },
            {
                "id": "func:b.py:parse_xml:10",
                "labels": ["Function", "_Node"],
                "props": {"name": "parse_xml", "file": "b.py"},
            },
        ]
        searcher = self._make_searcher_with_data(nodes)
        results = searcher.search("parse", label_filter="Class")
        # Only the Class node should survive the filter
        assert len(results) >= 1
        assert all("Class" in r["labels"] for r in results)
