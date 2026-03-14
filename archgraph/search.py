"""Hybrid search — BM25 + semantic search with Reciprocal Rank Fusion."""

from __future__ import annotations

import logging
import math
import re
from collections import Counter, defaultdict
from typing import Any

from archgraph.graph.neo4j_store import Neo4jStore
from archgraph.graph.schema import NodeLabel

logger = logging.getLogger(__name__)


class HybridSearcher:
    """Hybrid search combining BM25 keyword matching and graph-based relevance."""

    def __init__(self, store: Neo4jStore) -> None:
        self._store = store
        self._index: dict[str, dict[str, Any]] = {}
        self._idf_cache: dict[str, float] = {}

    def build_index(self) -> None:
        """Build search index from Neo4j graph."""
        # Index all searchable nodes
        nodes = self._store.query(
            "MATCH (n:_Node) "
            "WHERE n:Function OR n:Class OR n:File OR n:Struct OR n:Module "
            "RETURN n._id AS id, labels(n) AS labels, properties(n) AS props"
        )

        self._index = {}
        doc_freq: Counter[str] = Counter()

        for node in nodes:
            node_id = node["id"]
            props = node.get("props", {})

            # Extract searchable text
            text_parts = []
            for key in ["name", "file", "path", "body", "message", "summary"]:
                val = props.get(key, "")
                if val:
                    text_parts.append(str(val))

            text = " ".join(text_parts).lower()
            tokens = self._tokenize(text)

            self._index[node_id] = {
                "text": text,
                "tokens": tokens,
                "labels": node["labels"],
                "props": props,
                "tf": Counter(tokens),
            }

            # Document frequency
            unique_tokens = set(tokens)
            for token in unique_tokens:
                doc_freq[token] += 1

        # Compute IDF
        n_docs = len(self._index)
        self._idf_cache = {
            token: math.log((n_docs - freq + 0.5) / (freq + 0.5) + 1)
            for token, freq in doc_freq.items()
        }

        logger.info("Built search index with %d documents", n_docs)

    def search(
        self,
        query: str,
        top_k: int = 20,
        label_filter: str | None = None,
        bm25_weight: float = 0.7,
        graph_weight: float = 0.3,
    ) -> list[dict[str, Any]]:
        """Hybrid search combining BM25 and graph relevance.

        Args:
            query: Search query string
            top_k: Number of results to return
            label_filter: Optional label filter (e.g., "Function", "Class")
            bm25_weight: Weight for BM25 scores (default 0.7)
            graph_weight: Weight for graph relevance scores (default 0.3)

        Returns:
            List of scored results
        """
        if not self._index:
            self.build_index()

        query_tokens = self._tokenize(query.lower())
        if not query_tokens:
            return []

        # BM25 scores
        bm25_scores = self._bm25_search(query_tokens)

        # Graph-based relevance (security-sensitive nodes get boost)
        graph_scores = self._graph_relevance(query_tokens)

        # Reciprocal Rank Fusion
        results = self._fuse_scores(
            bm25_scores, graph_scores, bm25_weight, graph_weight
        )

        # Filter by label if specified
        if label_filter:
            results = [
                r for r in results
                if label_filter in self._index.get(r["id"], {}).get("labels", [])
            ]

        # Enrich results with node properties
        enriched = []
        for r in results[:top_k]:
            node_data = self._index.get(r["id"], {})
            props = node_data.get("props", {})
            enriched.append({
                "id": r["id"],
                "score": round(r["score"], 4),
                "name": props.get("name", ""),
                "file": props.get("file", props.get("path", "")),
                "labels": node_data.get("labels", []),
                "snippet": self._get_snippet(node_data.get("text", ""), query_tokens),
                "security": {
                    "is_input_source": props.get("is_input_source", False),
                    "is_dangerous_sink": props.get("is_dangerous_sink", False),
                },
            })

        return enriched

    def _tokenize(self, text: str) -> list[str]:
        """Tokenize text into searchable tokens."""
        # Split on non-alphanumeric, keep camelCase parts
        tokens = re.findall(r"[a-z0-9]+", text.lower())
        # Add camelCase splits
        expanded = []
        for token in tokens:
            expanded.append(token)
            # Split camelCase: "parseData" -> ["parse", "data"]
            parts = re.findall(r"[a-z]+|[A-Z][a-z]*", token)
            if len(parts) > 1:
                expanded.extend(p.lower() for p in parts if len(p) > 1)
        return expanded

    def _bm25_search(self, query_tokens: list[str]) -> dict[str, float]:
        """BM25 scoring for all documents."""
        k1, b = 1.5, 0.75
        avg_dl = sum(len(d["tokens"]) for d in self._index.values()) / max(len(self._index), 1)

        scores: dict[str, float] = {}

        for doc_id, doc_data in self._index.items():
            tf = doc_data["tf"]
            dl = len(doc_data["tokens"])

            score = 0.0
            for token in query_tokens:
                if token not in tf:
                    continue
                idf = self._idf_cache.get(token, 0)
                tf_val = tf[token]
                tf_norm = (tf_val * (k1 + 1)) / (tf_val + k1 * (1 - b + b * dl / avg_dl))
                score += idf * tf_norm

            if score > 0:
                scores[doc_id] = score

        return scores

    def _graph_relevance(self, query_tokens: list[str]) -> dict[str, float]:
        """Boost scores based on graph properties (security, connectivity)."""
        scores: dict[str, float] = {}

        for doc_id, doc_data in self._index.items():
            score = 0.0
            props = doc_data.get("props", {})

            # Security-sensitive nodes get a boost
            if props.get("is_input_source"):
                score += 2.0
            if props.get("is_dangerous_sink"):
                score += 2.0
            if props.get("is_crypto"):
                score += 1.0
            if props.get("is_exported"):
                score += 0.5

            # Exact name match gets a big boost
            name = props.get("name", "").lower()
            query_lower = " ".join(query_tokens)
            if name == query_lower:
                score += 5.0
            elif name and query_lower in name:
                score += 2.0

            if score > 0:
                scores[doc_id] = score

        return scores

    def _fuse_scores(
        self,
        bm25_scores: dict[str, float],
        graph_scores: dict[str, float],
        bm25_weight: float,
        graph_weight: float,
    ) -> list[dict[str, Any]]:
        """Combine scores using Reciprocal Rank Fusion."""
        all_ids = set(bm25_scores.keys()) | set(graph_scores.keys())

        # Normalize scores to [0, 1]
        bm25_max = max(bm25_scores.values()) if bm25_scores else 1.0
        graph_max = max(graph_scores.values()) if graph_scores else 1.0

        fused: list[dict[str, Any]] = []

        for doc_id in all_ids:
            bm25_norm = bm25_scores.get(doc_id, 0) / bm25_max
            graph_norm = graph_scores.get(doc_id, 0) / graph_max

            # Weighted combination
            combined = bm25_weight * bm25_norm + graph_weight * graph_norm

            fused.append({"id": doc_id, "score": combined})

        fused.sort(key=lambda x: x["score"], reverse=True)
        return fused

    def _get_snippet(self, text: str, query_tokens: list[str], max_len: int = 150) -> str:
        """Extract a relevant snippet around query matches."""
        if not text:
            return ""

        text_lower = text.lower()
        best_pos = 0
        best_count = 0

        # Find position with most query token matches
        for pos in range(0, len(text), 20):
            window = text_lower[pos : pos + max_len]
            count = sum(1 for t in query_tokens if t in window)
            if count > best_count:
                best_count = count
                best_pos = pos

        snippet = text[best_pos : best_pos + max_len].strip()
        if best_pos > 0:
            snippet = "..." + snippet
        if best_pos + max_len < len(text):
            snippet = snippet + "..."

        return snippet
