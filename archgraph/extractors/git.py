"""Git history extractor — commits, authors, tags, and file change mapping."""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path

from archgraph.config import SECURITY_COMMIT_PATTERNS
from archgraph.extractors.base import BaseExtractor
from archgraph.graph.schema import GraphData, NodeLabel, EdgeType

logger = logging.getLogger(__name__)

_SECURITY_RE = [re.compile(p) for p in SECURITY_COMMIT_PATTERNS]


def _run_git(repo_path: Path, *args: str) -> str:
    """Run a git command and return stdout."""
    result = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        logger.warning("git %s failed: %s", " ".join(args), result.stderr[:200])
        return ""
    return result.stdout


class GitExtractor(BaseExtractor):
    """Extracts git commit history, authors, tags, and security fixes."""

    def __init__(self, max_commits: int = 10_000) -> None:
        self._max_commits = max_commits

    def extract(self, repo_path: Path, **kwargs: object) -> GraphData:
        graph = GraphData()

        # Check if repo has git
        git_dir = repo_path / ".git"
        if not git_dir.exists():
            logger.info("No .git directory found, skipping git extraction")
            return graph

        self._extract_commits(repo_path, graph)
        self._extract_tags(repo_path, graph)

        return graph

    def _extract_commits(self, repo_path: Path, graph: GraphData) -> None:
        """Extract commits with author and changed files."""
        # Format: hash|parent_hashes|author_name|author_email|date|subject|insertions|deletions
        log_format = "%H|%P|%aN|%aE|%aI|%s"
        raw = _run_git(
            repo_path,
            "log",
            f"--max-count={self._max_commits}",
            f"--format={log_format}",
            "--numstat",
        )
        if not raw:
            return

        current_commit: dict | None = None
        commit_files: list[str] = []

        for line in raw.split("\n"):
            line = line.strip()
            if not line:
                # Flush previous commit
                if current_commit:
                    self._add_commit(current_commit, commit_files, repo_path, graph)
                    current_commit = None
                    commit_files = []
                continue

            parts = line.split("|", 5)
            if len(parts) == 6 and len(parts[0]) == 40:
                # New commit line
                if current_commit:
                    self._add_commit(current_commit, commit_files, repo_path, graph)
                    commit_files = []

                current_commit = {
                    "hash": parts[0],
                    "parents": parts[1].split() if parts[1] else [],
                    "author_name": parts[2],
                    "author_email": parts[3],
                    "date": parts[4],
                    "message": parts[5],
                }
            elif "\t" in line and current_commit:
                # Numstat line: insertions\tdeletions\tfilepath
                stat_parts = line.split("\t")
                if len(stat_parts) >= 3:
                    commit_files.append(stat_parts[2])

        # Flush last commit
        if current_commit:
            self._add_commit(current_commit, commit_files, repo_path, graph)

    def _add_commit(
        self,
        commit: dict,
        files: list[str],
        repo_path: Path,
        graph: GraphData,
    ) -> None:
        """Add a commit node, author, and file relationships."""
        commit_id = f"commit:{commit['hash']}"
        graph.add_node(
            commit_id,
            NodeLabel.COMMIT,
            hash=commit["hash"],
            message=commit["message"][:500],
            date=commit["date"],
        )

        # Author
        author_id = f"author:{commit['author_email']}"
        graph.add_node(
            author_id,
            NodeLabel.AUTHOR,
            name=commit["author_name"],
            email=commit["author_email"],
        )
        graph.add_edge(commit_id, author_id, EdgeType.AUTHORED_BY)

        # Parent commits
        for parent_hash in commit["parents"]:
            parent_id = f"commit:{parent_hash}"
            graph.add_edge(commit_id, parent_id, EdgeType.PARENT)

        # File modifications
        for file_path in files:
            file_id = f"file:{file_path}"
            graph.add_edge(file_id, commit_id, EdgeType.MODIFIED_IN)

        # Security fix detection
        if self._is_security_commit(commit["message"]):
            fix_id = f"secfix:{commit['hash']}"
            graph.add_node(
                fix_id,
                NodeLabel.SECURITY_FIX,
                commit_hash=commit["hash"],
                description=commit["message"][:500],
            )
            graph.add_edge(fix_id, commit_id, EdgeType.FIXED_BY)

    def _is_security_commit(self, message: str) -> bool:
        """Check if a commit message indicates a security fix."""
        return any(rx.search(message) for rx in _SECURITY_RE)

    def _extract_tags(self, repo_path: Path, graph: GraphData) -> None:
        """Extract release tags."""
        raw = _run_git(repo_path, "tag", "-l", "--format=%(refname:short)|%(objectname:short)|%(*objectname:short)|%(creatordate:iso-strict)")
        if not raw:
            return

        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) < 2:
                continue
            tag_name = parts[0]
            # For annotated tags, the pointed-to commit is in parts[2]
            commit_hash = parts[2] if len(parts) > 2 and parts[2] else parts[1]
            date = parts[3] if len(parts) > 3 else ""

            tag_id = f"tag:{tag_name}"
            graph.add_node(
                tag_id,
                NodeLabel.TAG,
                name=tag_name,
                commit_hash=commit_hash,
                date=date,
            )

            # Link to commit
            commit_id = f"commit:{commit_hash}"
            graph.add_edge(commit_id, tag_id, EdgeType.TAGGED_AS)
