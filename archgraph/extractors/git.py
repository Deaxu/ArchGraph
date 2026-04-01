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
        encoding="utf-8",
        errors="replace",
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
        since_commit: str | None = kwargs.get("since_commit", None)  # type: ignore[assignment]

        # Check if repo has git
        git_dir = repo_path / ".git"
        if not git_dir.exists():
            logger.info("No .git directory found, skipping git extraction")
            return graph

        self._extract_commits(repo_path, graph, since_commit=since_commit)
        self._extract_tags(repo_path, graph)

        return graph

    def _extract_commits(
        self, repo_path: Path, graph: GraphData, *, since_commit: str | None = None
    ) -> None:
        """Extract commits with author and changed files."""
        # Format: hash|parent_hashes|author_name|author_email|date|subject
        log_format = "%H|%P|%aN|%aE|%aI|%s"
        cmd_args = [
            "log",
            f"--max-count={self._max_commits}",
            f"--format={log_format}",
            "--numstat",
        ]
        if since_commit:
            cmd_args.append(f"{since_commit}..HEAD")
        raw = _run_git(repo_path, *cmd_args)
        if not raw:
            msg = (
                "Git log returned no commits. "
                "If using --depth for shallow clone, try a larger depth."
            )
            logger.warning(msg)
            graph.warnings.append(msg)
            return

        current_commit: dict | None = None
        commit_files: list[dict] = []

        for line in raw.split("\n"):
            line = line.strip()

            # Try to detect a commit header line
            parts = line.split("|", 5) if line else []
            is_header = len(parts) == 6 and len(parts[0]) == 40 and all(
                c in "0123456789abcdef" for c in parts[0]
            )

            if is_header:
                # Flush previous commit before starting a new one
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
                    added = int(stat_parts[0]) if stat_parts[0].isdigit() else 0
                    deleted = int(stat_parts[1]) if stat_parts[1].isdigit() else 0
                    commit_files.append({
                        "path": stat_parts[2],
                        "lines_added": added,
                        "lines_deleted": deleted,
                    })
            # Blank lines are ignored — flush happens at next header or end

        # Flush last commit
        if current_commit:
            self._add_commit(current_commit, commit_files, repo_path, graph)

    def _add_commit(
        self,
        commit: dict,
        files: list[dict],
        repo_path: Path,
        graph: GraphData,
    ) -> None:
        """Add a commit node, author, and file relationships."""
        commit_id = f"commit:{commit['hash']}"

        total_added = sum(f["lines_added"] for f in files)
        total_deleted = sum(f["lines_deleted"] for f in files)

        graph.add_node(
            commit_id,
            NodeLabel.COMMIT,
            hash=commit["hash"],
            message=commit["message"][:500],
            date=commit["date"],
            total_insertions=total_added,
            total_deletions=total_deleted,
            files_changed=len(files),
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

        # File modifications — with per-file change stats
        for file_info in files:
            file_id = f"file:{file_info['path']}"
            graph.add_edge(
                file_id,
                commit_id,
                EdgeType.MODIFIED_IN,
                lines_added=file_info["lines_added"],
                lines_deleted=file_info["lines_deleted"],
            )

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

            # Link security fix directly to affected files
            for file_info in files:
                file_id = f"file:{file_info['path']}"
                graph.add_edge(fix_id, file_id, EdgeType.AFFECTS)

    def _is_security_commit(self, message: str) -> bool:
        """Check if a commit message indicates a security fix."""
        return any(rx.search(message) for rx in _SECURITY_RE)

    def _extract_tags(self, repo_path: Path, graph: GraphData) -> None:
        """Extract release tags."""
        raw = _run_git(
            repo_path, "tag", "-l",
            "--format=%(refname:short)|%(objectname)|%(*objectname)|%(creatordate:iso-strict)",
        )
        if not raw:
            return

        for line in raw.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) < 2:
                continue
            tag_name = parts[0]
            # For annotated tags, %(*objectname) gives the dereferenced commit hash
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

            # Link to commit (full hash — matches commit node IDs)
            commit_id = f"commit:{commit_hash}"
            graph.add_edge(commit_id, tag_id, EdgeType.TAGGED_AS)
