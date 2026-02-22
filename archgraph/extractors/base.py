"""Base extractor abstract class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from archgraph.graph.schema import GraphData


class BaseExtractor(ABC):
    """Abstract base class for all extractors."""

    @abstractmethod
    def extract(self, repo_path: Path, **kwargs: object) -> GraphData:
        """Extract graph data from a repository.

        Args:
            repo_path: Path to the repository root.
            **kwargs: Extractor-specific options.

        Returns:
            GraphData containing extracted nodes and edges.
        """
        ...
