"""Multi-repo registry — global index of all analyzed repositories."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_REGISTRY_DIR = Path.home() / ".archgraph"
_REGISTRY_FILE = _REGISTRY_DIR / "registry.json"


@dataclass
class RepoEntry:
    """A registered repository entry."""
    name: str
    path: str
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_database: str = "neo4j"
    languages: list[str] = field(default_factory=list)
    indexed_at: str = ""
    node_count: int = 0
    edge_count: int = 0
    clusters: int = 0
    processes: int = 0
    vulnerabilities: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RepoEntry:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class RepoRegistry:
    """Global registry for all analyzed repositories."""

    def __init__(self, registry_path: Path | None = None) -> None:
        self._path = registry_path or _REGISTRY_FILE
        self._repos: dict[str, RepoEntry] = {}
        self._load()

    def _load(self) -> None:
        """Load registry from disk."""
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            for name, entry_data in data.get("repos", {}).items():
                self._repos[name] = RepoEntry.from_dict(entry_data)
            logger.info("Loaded %d repos from registry", len(self._repos))
        except Exception as e:
            logger.warning("Failed to load registry: %s", e)

    def _save(self) -> None:
        """Save registry to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "updated_at": datetime.now().isoformat(),
            "repos": {name: entry.to_dict() for name, entry in self._repos.items()},
        }
        self._path.write_text(json.dumps(data, indent=2))

    def register(
        self,
        repo_path: Path,
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_database: str = "neo4j",
        languages: list[str] | None = None,
        stats: dict[str, Any] | None = None,
    ) -> RepoEntry:
        """Register or update a repository."""
        name = repo_path.name
        entry = RepoEntry(
            name=name,
            path=str(repo_path.resolve()),
            neo4j_uri=neo4j_uri,
            neo4j_database=neo4j_database,
            languages=languages or [],
            indexed_at=datetime.now().isoformat(),
        )

        if stats:
            entry.node_count = stats.get("node_count", 0)
            entry.edge_count = stats.get("edge_count", 0)
            entry.clusters = stats.get("clusters", 0)
            entry.processes = stats.get("processes", 0)
            entry.vulnerabilities = stats.get("vulnerabilities", 0)

        self._repos[name] = entry
        self._save()
        logger.info("Registered repo: %s (%s)", name, entry.path)
        return entry

    def unregister(self, name: str) -> bool:
        """Unregister a repository."""
        if name in self._repos:
            del self._repos[name]
            self._save()
            logger.info("Unregistered repo: %s", name)
            return True
        return False

    def get(self, name: str) -> RepoEntry | None:
        """Get a repo entry by name."""
        return self._repos.get(name)

    def list_repos(self) -> list[RepoEntry]:
        """List all registered repos."""
        return list(self._repos.values())

    def find_by_path(self, path: Path) -> RepoEntry | None:
        """Find a repo by its filesystem path."""
        resolved = str(path.resolve())
        for entry in self._repos.values():
            if entry.path == resolved:
                return entry
        return None


# Singleton instance
_registry: RepoRegistry | None = None


def get_registry() -> RepoRegistry:
    """Get the global registry singleton."""
    global _registry
    if _registry is None:
        _registry = RepoRegistry()
    return _registry
