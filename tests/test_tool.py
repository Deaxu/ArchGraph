"""Tests for the ArchGraphTool (without requiring Neo4j)."""

import pytest

from archgraph.tool.archgraph_tool import ArchGraphTool

pytestmark = pytest.mark.api


def test_tool_properties():
    tool = ArchGraphTool()
    assert tool.name == "archgraph"
    assert "Cypher" in tool.description
    assert "graph" in tool.description.lower()


def test_tool_context_manager():
    """Test that context manager doesn't crash without Neo4j."""
    tool = ArchGraphTool(neo4j_uri="bolt://localhost:99999")
    # Should not raise on creation
    assert tool.name == "archgraph"
