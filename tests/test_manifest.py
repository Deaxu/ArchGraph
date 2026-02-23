"""Tests for manifest I/O, change detection, and file scanning."""

import json
import textwrap
from pathlib import Path

import pytest

from archgraph.manifest import (
    ChangeSet,
    FileEntry,
    Manifest,
    build_manifest_from_files,
    compute_changeset,
    compute_dependencies_hash,
    delete_manifest,
    get_git_head,
    load_manifest,
    save_manifest,
    scan_current_files,
)


# ── Manifest I/O Tests ──────────────────────────────────────────────────────


class TestManifestIO:
    def test_save_load_roundtrip(self, tmp_path: Path) -> None:
        """save → load should return identical manifest."""
        files = {
            "src/main.c": FileEntry(hash="aaa", size=100, language="c"),
            "src/util.rs": FileEntry(hash="bbb", size=200, language="rust"),
        }
        original = build_manifest_from_files(tmp_path, files, git_head="abc123", deps_hash="def456")
        save_manifest(tmp_path, original)

        loaded = load_manifest(tmp_path)
        assert loaded is not None
        assert loaded.version == original.version
        assert loaded.repo_path == original.repo_path
        assert loaded.git_head == "abc123"
        assert loaded.dependencies_hash == "def456"
        assert len(loaded.files) == 2
        assert loaded.files["src/main.c"].hash == "aaa"
        assert loaded.files["src/main.c"].size == 100
        assert loaded.files["src/main.c"].language == "c"
        assert loaded.files["src/util.rs"].hash == "bbb"

    def test_load_missing_returns_none(self, tmp_path: Path) -> None:
        """Loading from a directory with no manifest should return None."""
        assert load_manifest(tmp_path) is None

    def test_load_corrupt_json_returns_none(self, tmp_path: Path) -> None:
        """Corrupt JSON should return None."""
        manifest_dir = tmp_path / ".archgraph"
        manifest_dir.mkdir()
        (manifest_dir / "manifest.json").write_text("not valid json {{{", encoding="utf-8")
        assert load_manifest(tmp_path) is None

    def test_load_version_mismatch_returns_none(self, tmp_path: Path) -> None:
        """Version mismatch should return None."""
        manifest_dir = tmp_path / ".archgraph"
        manifest_dir.mkdir()
        data = {"version": 999, "files": {}}
        (manifest_dir / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
        assert load_manifest(tmp_path) is None

    def test_delete_manifest(self, tmp_path: Path) -> None:
        """delete_manifest should remove the file."""
        files = {"a.c": FileEntry(hash="x", size=10, language="c")}
        m = build_manifest_from_files(tmp_path, files)
        save_manifest(tmp_path, m)
        assert (tmp_path / ".archgraph" / "manifest.json").exists()

        delete_manifest(tmp_path)
        assert not (tmp_path / ".archgraph" / "manifest.json").exists()

    def test_delete_manifest_noop_if_missing(self, tmp_path: Path) -> None:
        """delete_manifest should not raise if no manifest exists."""
        delete_manifest(tmp_path)  # should not raise


# ── ChangeSet Tests ──────────────────────────────────────────────────────────


class TestChangeSet:
    def _make_manifest(self, files: dict[str, FileEntry], **kwargs: str) -> Manifest:
        return Manifest(
            version=1,
            extracted_at="2026-01-01T00:00:00Z",
            repo_path="/tmp/repo",
            files=files,
            git_head=kwargs.get("git_head", ""),
            dependencies_hash=kwargs.get("deps_hash", ""),
        )

    def test_added_files(self) -> None:
        old = self._make_manifest({})
        current = {"new.c": FileEntry(hash="aaa", size=50, language="c")}
        cs = compute_changeset(old, current)
        assert cs.added_files == {"new.c"}
        assert not cs.deleted_files
        assert not cs.modified_files
        assert cs.has_changes

    def test_deleted_files(self) -> None:
        old = self._make_manifest({"old.c": FileEntry(hash="aaa", size=50, language="c")})
        cs = compute_changeset(old, {})
        assert cs.deleted_files == {"old.c"}
        assert not cs.added_files
        assert cs.has_changes

    def test_modified_files(self) -> None:
        old = self._make_manifest({"main.c": FileEntry(hash="aaa", size=50, language="c")})
        current = {"main.c": FileEntry(hash="bbb", size=60, language="c")}
        cs = compute_changeset(old, current)
        assert cs.modified_files == {"main.c"}
        assert not cs.added_files
        assert not cs.deleted_files
        assert cs.has_changes

    def test_no_changes(self) -> None:
        files = {"main.c": FileEntry(hash="aaa", size=50, language="c")}
        old = self._make_manifest(files)
        cs = compute_changeset(old, dict(files))
        assert not cs.added_files
        assert not cs.modified_files
        assert not cs.deleted_files
        assert not cs.deps_changed
        assert not cs.has_changes

    def test_deps_changed(self) -> None:
        old = self._make_manifest({}, deps_hash="old_hash")
        cs = compute_changeset(old, {}, current_deps_hash="new_hash")
        assert cs.deps_changed
        assert cs.has_changes

    def test_changed_files_combines_added_and_modified(self) -> None:
        old = self._make_manifest({"a.c": FileEntry(hash="aaa", size=10, language="c")})
        current = {
            "a.c": FileEntry(hash="bbb", size=20, language="c"),  # modified
            "b.c": FileEntry(hash="ccc", size=30, language="c"),  # added
        }
        cs = compute_changeset(old, current)
        assert cs.changed_files == {"a.c", "b.c"}


# ── File Scanning Tests ──────────────────────────────────────────────────────


class TestScanFiles:
    def test_discovers_source_files(self, tmp_path: Path) -> None:
        """Should find .c, .rs, .go files."""
        (tmp_path / "main.c").write_text("int main() {}", encoding="utf-8")
        (tmp_path / "lib.rs").write_text("fn main() {}", encoding="utf-8")
        (tmp_path / "README.md").write_text("# Hello", encoding="utf-8")  # not a source file

        files = scan_current_files(tmp_path)
        assert "main.c" in files
        assert "lib.rs" in files
        assert "README.md" not in files

    def test_skips_skip_dirs(self, tmp_path: Path) -> None:
        """Should skip .git, node_modules, etc."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config.c").write_text("// git internal", encoding="utf-8")

        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "index.js").write_text("// dep", encoding="utf-8")

        (tmp_path / "main.c").write_text("int main() {}", encoding="utf-8")

        files = scan_current_files(tmp_path)
        assert "main.c" in files
        # Files in skipped directories should not appear
        assert not any(".git" in k for k in files)
        assert not any("node_modules" in k for k in files)

    def test_correct_hash(self, tmp_path: Path) -> None:
        """SHA-256 should be deterministic for the same content."""
        content = "int main() { return 0; }"
        (tmp_path / "main.c").write_text(content, encoding="utf-8")

        files = scan_current_files(tmp_path)
        entry = files["main.c"]
        assert len(entry.hash) == 64  # SHA-256 hex digest
        assert entry.language == "c"
        assert entry.size > 0

        # Rescan — same hash
        files2 = scan_current_files(tmp_path)
        assert files2["main.c"].hash == entry.hash


# ── Dependencies Hash Tests ─────────────────────────────────────────────────


class TestDependenciesHash:
    def test_no_manifests_returns_empty(self, tmp_path: Path) -> None:
        """No dependency files → empty string."""
        (tmp_path / "main.c").write_text("int x;", encoding="utf-8")
        assert compute_dependencies_hash(tmp_path) == ""

    def test_hash_changes_with_content(self, tmp_path: Path) -> None:
        """Changing Cargo.toml content should produce a different hash."""
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[package]\nname = "foo"', encoding="utf-8")
        hash1 = compute_dependencies_hash(tmp_path)

        cargo.write_text('[package]\nname = "bar"', encoding="utf-8")
        hash2 = compute_dependencies_hash(tmp_path)

        assert hash1
        assert hash2
        assert hash1 != hash2


# ── Build Manifest Tests ─────────────────────────────────────────────────────


class TestBuildManifest:
    def test_creates_correct_manifest(self, tmp_path: Path) -> None:
        files = {"main.c": FileEntry(hash="aaa", size=50, language="c")}
        m = build_manifest_from_files(tmp_path, files, git_head="abc", deps_hash="def")
        assert m.version == 1
        assert m.repo_path == str(tmp_path)
        assert m.git_head == "abc"
        assert m.dependencies_hash == "def"
        assert len(m.files) == 1
        assert m.extracted_at  # should be non-empty ISO timestamp
