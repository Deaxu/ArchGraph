"""Manifest I/O and change detection for incremental extraction."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from archgraph.config import EXTENSION_MAP, SKIP_DIRS, SKIP_FILES

logger = logging.getLogger(__name__)

_MANIFEST_VERSION = 1
_MANIFEST_DIR = ".archgraph"
_MANIFEST_FILE = "manifest.json"


@dataclass
class FileEntry:
    """State of a single source file."""

    hash: str
    size: int
    language: str


@dataclass
class Manifest:
    """Snapshot of the repository state at extraction time."""

    version: int
    extracted_at: str
    repo_path: str
    files: dict[str, FileEntry]
    git_head: str = ""
    dependencies_hash: str = ""


@dataclass
class ChangeSet:
    """Diff between old manifest and current file state."""

    added_files: set[str] = field(default_factory=set)
    modified_files: set[str] = field(default_factory=set)
    deleted_files: set[str] = field(default_factory=set)
    git_head_old: str = ""
    git_head_new: str = ""
    deps_changed: bool = False

    @property
    def changed_files(self) -> set[str]:
        """All files that need re-extraction (added + modified)."""
        return self.added_files | self.modified_files

    @property
    def has_changes(self) -> bool:
        return bool(self.added_files or self.modified_files or self.deleted_files or self.deps_changed)


def _manifest_path(repo_path: Path) -> Path:
    return repo_path / _MANIFEST_DIR / _MANIFEST_FILE


def load_manifest(repo_path: Path) -> Manifest | None:
    """Load manifest from .archgraph/manifest.json. Returns None if missing or invalid."""
    path = _manifest_path(repo_path)
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Corrupt manifest, will do full extraction: %s", e)
        return None

    if data.get("version") != _MANIFEST_VERSION:
        logger.info("Manifest version mismatch (got %s, need %d), full extraction required",
                     data.get("version"), _MANIFEST_VERSION)
        return None

    files: dict[str, FileEntry] = {}
    for rel_path, entry in data.get("files", {}).items():
        files[rel_path] = FileEntry(
            hash=entry["hash"],
            size=entry["size"],
            language=entry["language"],
        )

    return Manifest(
        version=data["version"],
        extracted_at=data.get("extracted_at", ""),
        repo_path=data.get("repo_path", ""),
        files=files,
        git_head=data.get("git_head", ""),
        dependencies_hash=data.get("dependencies_hash", ""),
    )


def save_manifest(repo_path: Path, manifest: Manifest) -> None:
    """Write manifest to .archgraph/manifest.json."""
    path = _manifest_path(repo_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data: dict[str, Any] = {
        "version": manifest.version,
        "extracted_at": manifest.extracted_at,
        "repo_path": manifest.repo_path,
        "files": {
            rel: {"hash": fe.hash, "size": fe.size, "language": fe.language}
            for rel, fe in manifest.files.items()
        },
        "git_head": manifest.git_head,
        "dependencies_hash": manifest.dependencies_hash,
    }

    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Saved manifest with %d files to %s", len(manifest.files), path)


def delete_manifest(repo_path: Path) -> None:
    """Delete the manifest file."""
    path = _manifest_path(repo_path)
    if path.exists():
        path.unlink()
        logger.info("Deleted manifest at %s", path)


def _file_sha256(path: Path) -> str:
    """Compute SHA-256 of file contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_current_files(repo_path: Path) -> dict[str, FileEntry]:
    """Walk the repo and return a dict of rel_path -> FileEntry for source files."""
    files: dict[str, FileEntry] = {}

    for root, dirs, filenames in os.walk(repo_path):
        # Skip hidden/build directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in filenames:
            if fname in SKIP_FILES:
                continue
            fpath = Path(root) / fname
            ext = fpath.suffix
            lang = EXTENSION_MAP.get(ext)
            if lang is None:
                continue

            rel = str(fpath.relative_to(repo_path)).replace("\\", "/")
            try:
                size = fpath.stat().st_size
                fhash = _file_sha256(fpath)
                files[rel] = FileEntry(hash=fhash, size=size, language=lang)
            except OSError:
                logger.debug("Could not stat %s, skipping", fpath)

    return files


def compute_changeset(
    old_manifest: Manifest,
    current_files: dict[str, FileEntry],
    current_git_head: str = "",
    current_deps_hash: str = "",
) -> ChangeSet:
    """Compute the diff between old manifest and current file state."""
    old_files = old_manifest.files
    old_set = set(old_files.keys())
    new_set = set(current_files.keys())

    added = new_set - old_set
    deleted = old_set - new_set
    common = old_set & new_set

    modified: set[str] = set()
    for rel in common:
        if old_files[rel].hash != current_files[rel].hash:
            modified.add(rel)

    deps_changed = bool(
        current_deps_hash and old_manifest.dependencies_hash != current_deps_hash
    )

    return ChangeSet(
        added_files=added,
        modified_files=modified,
        deleted_files=deleted,
        git_head_old=old_manifest.git_head,
        git_head_new=current_git_head,
        deps_changed=deps_changed,
    )


_DEP_MANIFESTS = frozenset({
    "Cargo.toml", "go.mod", "package.json", "build.gradle", "build.gradle.kts",
    "Podfile", "CMakeLists.txt", "conanfile.txt", "vcpkg.json", "Package.swift",
})


def compute_dependencies_hash(repo_path: Path) -> str:
    """Hash all dependency manifest files for change detection."""
    h = hashlib.sha256()
    found = False

    for root, dirs, filenames in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in sorted(filenames):
            if fname in _DEP_MANIFESTS:
                fpath = Path(root) / fname
                try:
                    h.update(fpath.read_bytes())
                    found = True
                except OSError:
                    pass

    return h.hexdigest() if found else ""


def get_git_head(repo_path: Path) -> str:
    """Get current HEAD commit hash. Returns empty string if not a git repo."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ""


def build_manifest_from_files(
    repo_path: Path,
    files: dict[str, FileEntry],
    git_head: str = "",
    deps_hash: str = "",
) -> Manifest:
    """Create a Manifest object from the given file entries."""
    return Manifest(
        version=_MANIFEST_VERSION,
        extracted_at=datetime.now(timezone.utc).isoformat(),
        repo_path=str(repo_path),
        files=files,
        git_head=git_head,
        dependencies_hash=deps_hash,
    )
