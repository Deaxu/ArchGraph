"""Git churn enrichment — calculates file and function change frequency."""

from __future__ import annotations

import logging
import subprocess
from collections import Counter
from pathlib import Path

from archgraph.graph.schema import GraphData, NodeLabel

logger = logging.getLogger(__name__)


def _run_git(repo_path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    return result.stdout if result.returncode == 0 else ""


class ChurnEnricher:
    """Enriches File nodes with git churn (change frequency) data."""

    def enrich(self, graph: GraphData, repo_path: Path) -> int:
        """Add churn_count and last_modified to File nodes. Returns count of enriched nodes."""
        git_dir = repo_path / ".git"
        if not git_dir.exists():
            return 0

        # Get change counts per file
        raw = _run_git(repo_path, "log", "--name-only", "--format=")
        if not raw:
            return 0

        file_counts: Counter[str] = Counter()
        for line in raw.splitlines():
            line = line.strip()
            if line:
                file_counts[line] += 1

        # Get last modification date per file
        last_modified: dict[str, str] = {}
        for file_path in file_counts:
            date = _run_git(
                repo_path, "log", "-1", "--format=%aI", "--", file_path
            ).strip()
            if date:
                last_modified[file_path] = date

        enriched = 0
        for node in graph.nodes:
            if node.label != NodeLabel.FILE:
                continue
            path = node.properties.get("path", "")
            if path in file_counts:
                node.properties["churn_count"] = file_counts[path]
                if path in last_modified:
                    node.properties["last_modified"] = last_modified[path]
                enriched += 1

        logger.info("Enriched %d files with churn data", enriched)
        return enriched
