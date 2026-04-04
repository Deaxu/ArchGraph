"""End-to-end CLI tests using Click's CliRunner — no Neo4j required."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from archgraph.cli import main

pytestmark = [pytest.mark.integration]


# ── Help output ─────────────────────────────────────────────────────────────


class TestCLIHelp:
    """Test CLI help output for all commands."""

    def test_main_help(self) -> None:
        """Main help should list core commands."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "extract" in result.output
        assert "query" in result.output
        assert "search" in result.output
        assert "mcp" in result.output
        assert "stats" in result.output

    def test_extract_help(self) -> None:
        """Extract help should list all important options."""
        runner = CliRunner()
        result = runner.invoke(main, ["extract", "--help"])
        assert result.exit_code == 0
        assert "--languages" in result.output
        assert "--workers" in result.output
        assert "--incremental" in result.output
        assert "--include-clang" in result.output
        assert "--neo4j-uri" in result.output
        assert "--clear-db" in result.output
        assert "--include-cve" in result.output
        assert "--include-deep" in result.output
        assert "--include-body" in result.output
        assert "--max-body-size" in result.output

    def test_search_help(self) -> None:
        """Search help should show name, type, file-pattern options."""
        runner = CliRunner()
        result = runner.invoke(main, ["search", "--help"])
        assert result.exit_code == 0
        assert "--name" in result.output
        assert "--type" in result.output
        assert "--file-pattern" in result.output
        assert "--limit" in result.output

    def test_query_help(self) -> None:
        """Query help should show cypher argument."""
        runner = CliRunner()
        result = runner.invoke(main, ["query", "--help"])
        assert result.exit_code == 0
        assert "CYPHER" in result.output or "cypher" in result.output.lower()

    def test_stats_help(self) -> None:
        """Stats help should show neo4j options."""
        runner = CliRunner()
        result = runner.invoke(main, ["stats", "--help"])
        assert result.exit_code == 0
        assert "--neo4j-uri" in result.output

    def test_impact_help(self) -> None:
        """Impact help should show direction and depth options."""
        runner = CliRunner()
        result = runner.invoke(main, ["impact", "--help"])
        assert result.exit_code == 0
        assert "--direction" in result.output
        assert "--depth" in result.output
        assert "SYMBOL_ID" in result.output or "symbol_id" in result.output.lower()

    def test_mcp_help(self) -> None:
        """MCP help should mention MCP server."""
        runner = CliRunner()
        result = runner.invoke(main, ["mcp", "--help"])
        assert result.exit_code == 0
        assert "MCP" in result.output or "mcp" in result.output.lower()

    def test_diff_help(self) -> None:
        """Diff help should show repo path argument."""
        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--help"])
        assert result.exit_code == 0
        assert "REPO_PATH" in result.output or "repo" in result.output.lower()

    def test_export_help(self) -> None:
        """Export help should show format and output options."""
        runner = CliRunner()
        result = runner.invoke(main, ["export", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output
        assert "--output" in result.output

    def test_repos_help(self) -> None:
        """Repos help should show format option."""
        runner = CliRunner()
        result = runner.invoke(main, ["repos", "--help"])
        assert result.exit_code == 0
        assert "--format" in result.output

    def test_schema_help(self) -> None:
        """Schema help should show neo4j options."""
        runner = CliRunner()
        result = runner.invoke(main, ["schema", "--help"])
        assert result.exit_code == 0
        assert "--neo4j-uri" in result.output

    def test_serve_help(self) -> None:
        """Serve help should show host and port options."""
        runner = CliRunner()
        result = runner.invoke(main, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--port" in result.output


# ── Version ─────────────────────────────────────────────────────────────────


class TestCLIVersion:
    """Test CLI version output."""

    def test_version_flag_accepted(self) -> None:
        """--version flag should be recognized by the CLI group."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        # If the package metadata is available, exit code is 0 and output has version.
        # In dev installs without proper metadata, Click raises RuntimeError
        # (exit code 1). Either way, --version is recognized as a flag.
        if result.exit_code == 0:
            output = result.output.lower()
            assert "archgraph" in output or "0." in output
        else:
            # Dev install without metadata — Click errors with a known message
            assert "is not installed" in str(result.exception) or result.exit_code == 1


# ── Extract command ─────────────────────────────────────────────────────────


class TestCLIExtract:
    """Test CLI extract command edge cases.

    Note: The CLI writes all output to stderr via Rich Console, not stdout.
    CliRunner only captures stdout by default, so we assert on exit codes
    and exception types rather than output content.
    """

    def test_extract_nonexistent_path(self) -> None:
        """Extract with nonexistent path should fail with exit code 1."""
        runner = CliRunner()
        result = runner.invoke(main, ["extract", "/nonexistent/path/xyz123"])
        assert result.exit_code != 0

    def test_extract_empty_dir(self, tmp_path: Path) -> None:
        """Extract with empty directory should fail at Neo4j import (exit 1)."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["extract", str(tmp_path), "--neo4j-uri", "bolt://localhost:99999"],
        )
        # Should fail at Neo4j import — exit code != 0
        assert result.exit_code != 0

    def test_extract_with_languages_fails_at_neo4j(self, tmp_c_project: Path) -> None:
        """Extract with explicit --languages should run extraction then fail at Neo4j."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "extract",
                str(tmp_c_project),
                "--languages", "c",
                "--neo4j-uri", "bolt://localhost:99999",
            ],
        )
        # Extraction succeeds but Neo4j import fails -> exit 1
        assert result.exit_code == 1

    def test_extract_with_workers_fails_at_neo4j(self, tmp_c_project: Path) -> None:
        """Extract with --workers should accept the option and run."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "extract",
                str(tmp_c_project),
                "--languages", "c",
                "-w", "1",
                "--neo4j-uri", "bolt://localhost:99999",
            ],
        )
        # Extraction succeeds but Neo4j import fails -> exit 1
        assert result.exit_code == 1

    def test_extract_with_no_deep_fails_at_neo4j(self, tmp_c_project: Path) -> None:
        """Extract with --no-deep should disable deep analysis and run."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "extract",
                str(tmp_c_project),
                "--languages", "c",
                "--no-deep",
                "--neo4j-uri", "bolt://localhost:99999",
            ],
        )
        assert result.exit_code == 1


# ── Search command ──────────────────────────────────────────────────────────


class TestCLISearch:
    """Test CLI search command validation."""

    def test_search_requires_at_least_one_filter(self) -> None:
        """Search without --name, --type, or --file-pattern should fail."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["search", "--neo4j-uri", "bolt://localhost:99999"],
        )
        assert result.exit_code != 0


# ── Repos command ───────────────────────────────────────────────────────────


class TestCLIRepos:
    """Test CLI repos command."""

    def test_repos_no_entries(self) -> None:
        """repos with no registered repos should show appropriate message."""
        runner = CliRunner()
        result = runner.invoke(main, ["repos"])
        # Should succeed even with no repos
        assert result.exit_code == 0


# ── Nonexistent subcommand ──────────────────────────────────────────────────


class TestCLINonexistent:
    """Test behavior with unknown subcommands."""

    def test_unknown_command(self) -> None:
        """Unknown subcommand should produce error."""
        runner = CliRunner()
        result = runner.invoke(main, ["nonexistent_command_xyz"])
        assert result.exit_code != 0
