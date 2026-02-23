"""Tests for Neo4j store with mocked driver — APOC detection."""

from unittest.mock import MagicMock, patch

import pytest

from archgraph.graph.neo4j_store import Neo4jStore


class TestApocDetection:
    """Test APOC auto-detection logic using mocked Neo4j sessions."""

    def _make_store(self) -> Neo4jStore:
        """Create a Neo4jStore with a mocked driver."""
        store = Neo4jStore(uri="bolt://mock:7687")
        store._driver = MagicMock()  # bypass real connection
        return store

    def test_apoc_available(self) -> None:
        """_detect_apoc returns True when APOC procedures exist."""
        store = self._make_store()

        # Mock the session context manager and query result
        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_record = {"cnt": 1}
        mock_result.single.return_value = mock_record
        mock_session.run.return_value = mock_result
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        store._driver.session.return_value = mock_session

        assert store._detect_apoc() is True

        # Result should be cached
        assert store._apoc_available is True
        assert store._detect_apoc() is True  # cached, no re-query

    def test_apoc_unavailable(self) -> None:
        """_detect_apoc returns False when APOC is not installed."""
        store = self._make_store()

        # Mock session.run to raise an exception (APOC not installed)
        mock_session = MagicMock()
        mock_session.run.side_effect = Exception("Unknown procedure: apoc.help")
        mock_session.__enter__ = MagicMock(return_value=mock_session)
        mock_session.__exit__ = MagicMock(return_value=False)
        store._driver.session.return_value = mock_session

        assert store._detect_apoc() is False

        # Result should be cached
        assert store._apoc_available is False
