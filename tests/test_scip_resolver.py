"""Tests for SCIP-based call resolution."""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from archgraph.graph.schema import GraphData, Node, NodeLabel, EdgeType


# ── Task 1: Proto Import ─────────────────────────────────────────────────────


class TestScipProto:
    def test_import_scip_pb2(self):
        from archgraph.extractors import scip_pb2
        idx = scip_pb2.Index()
        assert hasattr(idx, "documents")
        assert hasattr(idx, "metadata")

    def test_create_mock_index(self):
        from archgraph.extractors import scip_pb2
        idx = scip_pb2.Index()
        doc = idx.documents.add()
        doc.relative_path = "src/main.ts"
        occ = doc.occurrences.add()
        occ.symbol = "test_symbol"
        occ.symbol_roles = 1
        occ.range.extend([10, 0, 10, 5])
        assert len(idx.documents) == 1
        assert idx.documents[0].occurrences[0].symbol == "test_symbol"
