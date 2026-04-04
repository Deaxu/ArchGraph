"""Tests for Neo4j store with mocked driver — APOC detection."""

from unittest.mock import MagicMock, patch

import pytest

from archgraph.graph.neo4j_store import Neo4jStore
from archgraph.graph.schema import GraphData, Node

pytestmark = pytest.mark.core


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


class TestRepoIsolation:
    """Test repo property injection and per-repo clear."""

    def _make_store(self) -> Neo4jStore:
        store = Neo4jStore(uri="bolt://mock:7687")
        store._driver = MagicMock()
        store._apoc_available = False  # force non-APOC path
        return store

    def _make_session(self, store: Neo4jStore) -> MagicMock:
        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        store._driver.session.return_value = session
        return session

    def test_import_graph_injects_repo_property(self) -> None:
        """import_graph adds repo property to every node record."""
        store = self._make_store()
        session = self._make_session(store)

        captured: list[list[dict]] = []
        session.run.side_effect = lambda q, **kw: captured.append(kw.get("records", []))

        node = Node(id="func:src/foo.py:bar:1", label="Function", properties={"name": "bar"})
        graph = GraphData(nodes=[node], edges=[])

        store.import_graph(graph, repo_name="my_repo")

        all_props = [r for batch in captured for r in batch]
        assert any(r.get("repo") == "my_repo" for r in all_props)

    def test_clear_repo_uses_repo_filter(self) -> None:
        """clear_repo only deletes nodes with matching repo property."""
        store = self._make_store()
        session = self._make_session(store)

        mock_result = MagicMock()
        mock_result.single.return_value = {"deleted": 0}
        session.run.return_value = mock_result

        store.clear_repo("my_repo")

        cypher = session.run.call_args[0][0]
        assert "repo" in cypher
        # Must NOT be a global delete (no bare MATCH (n) without filter)
        assert "MATCH (n)" not in cypher
