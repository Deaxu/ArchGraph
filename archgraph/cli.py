"""CLI entry point for ArchGraph."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from archgraph.config import ExtractConfig
from archgraph.graph.builder import GraphBuilder
from archgraph.graph.neo4j_store import Neo4jStore

console = Console()

_GIT_URL_RE = re.compile(
    r"^(?:https?://|git@|ssh://)"  # https://, git@, ssh://
    r"|\.git$"                      # ends with .git
)


def _is_git_url(value: str) -> bool:
    """Check if the value looks like a git remote URL."""
    return bool(_GIT_URL_RE.search(value))


def _clone_repo(url: str, branch: str | None, depth: int | None) -> Path:
    """Clone a git repo to a temp directory and return the path."""
    tmp = Path(tempfile.mkdtemp(prefix="archgraph_clone_"))
    cmd = ["git", "clone"]
    if depth:
        cmd += ["--depth", str(depth)]
    if branch:
        cmd += ["--branch", branch]
    cmd += [url, str(tmp / "repo")]
    console.print(f"[bold]Cloning[/bold] [cyan]{url}[/cyan] ...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        console.print(f"[red]git clone failed:[/red] {result.stderr.strip()}")
        raise click.Abort()
    console.print("[green]Clone complete.[/green]")
    return tmp / "repo"


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)],
    )


@click.group()
@click.version_option(package_name="archgraph")
def main() -> None:
    """ArchGraph — Source code graph extraction & Cypher query tool."""
    pass


@main.command()
@click.argument("repo_path")
@click.option(
    "--languages", "-l",
    default="c,cpp,rust,java,go",
    help="Comma-separated list of languages to extract",
)
@click.option("--branch", "-b", default=None, help="Branch to clone (for git URLs)")
@click.option("--depth", "-d", type=int, default=None, help="Clone depth (for git URLs)")
@click.option("--neo4j-uri", default="bolt://localhost:7687",
              envvar="ARCHGRAPH_NEO4J_URI", help="Neo4j bolt URI")
@click.option("--neo4j-user", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_USER", help="Neo4j username")
@click.option("--neo4j-password", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_PASSWORD", help="Neo4j password")
@click.option("--neo4j-database", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_DATABASE", help="Neo4j database name")
@click.option("--include-git/--no-git", default=True, help="Include git history extraction")
@click.option("--include-deps/--no-deps", default=True, help="Include dependency extraction")
@click.option("--include-annotations/--no-annotations", default=True, help="Include annotations")
@click.option("--include-clang/--no-clang", default=False, help="Enable clang deep analysis")
@click.option("--include-deep/--no-deep", default=False, help="Enable tree-sitter deep analysis")
@click.option(
    "--compile-commands", type=click.Path(exists=True, path_type=Path), default=None,
    help="Path to compile_commands.json for clang analysis",
)
@click.option(
    "--workers", "-w", type=int, default=0,
    help="Number of worker threads (0=auto, 1=sequential)",
)
@click.option("--include-cve/--no-cve", default=False, help="Enable CVE enrichment via OSV API")
@click.option("--clear-db/--no-clear-db", default=False, help="Clear database before import")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def extract(
    repo_path: str,
    languages: str,
    branch: str | None,
    depth: int | None,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
    include_git: bool,
    include_deps: bool,
    include_annotations: bool,
    include_clang: bool,
    include_deep: bool,
    compile_commands: Path | None,
    workers: int,
    include_cve: bool,
    clear_db: bool,
    verbose: bool,
) -> None:
    """Extract code graph from a repository and import into Neo4j.

    REPO_PATH can be a local directory or a git URL (https/ssh).
    """
    _setup_logging(verbose)

    cloned_dir: Path | None = None
    if _is_git_url(repo_path):
        cloned_dir = _clone_repo(repo_path, branch, depth)
        resolved_path = cloned_dir
    else:
        resolved_path = Path(repo_path)
        if not resolved_path.is_dir():
            console.print(f"[red]Not a directory: {repo_path}[/red]")
            raise SystemExit(1)
        resolved_path = resolved_path.resolve()

    try:
        config = ExtractConfig(
            repo_path=resolved_path,
        languages=[l.strip() for l in languages.split(",")],
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
        neo4j_database=neo4j_database,
        include_git=include_git,
        include_deps=include_deps,
        include_annotations=include_annotations,
        include_clang=include_clang,
        clang_compile_commands=compile_commands,
        include_deep=include_deep,
        workers=workers,
        include_cve=include_cve,
    )

        console.print(
            f"\n[bold]ArchGraph[/bold] — Extracting from [cyan]{resolved_path}[/cyan]\n"
        )

        # Build graph
        start = time.time()
        builder = GraphBuilder(config)
        graph = builder.build()
        build_time = time.time() - start

        # Display stats
        stats = graph.stats()
        table = Table(title="Extraction Results")
        table.add_column("Type", style="cyan")
        table.add_column("Count", justify="right", style="green")

        for label, count in sorted(stats["nodes"].items()):
            table.add_row(f"Node: {label}", str(count))
        for etype, count in sorted(stats["edges"].items()):
            table.add_row(f"Edge: {etype}", str(count))

        console.print(table)
        console.print(f"\nExtraction took {build_time:.1f}s")

        # Import into Neo4j
        console.print(f"\n[bold]Importing into Neo4j[/bold] at {neo4j_uri}...")
        try:
            with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
                if clear_db:
                    console.print("[yellow]Clearing existing data...[/yellow]")
                    store.clear()

                store.create_indexes()
                import_start = time.time()
                result = store.import_graph(graph)
                import_time = time.time() - import_start

                console.print(
                    f"[green]Imported {result['nodes_imported']} nodes and "
                    f"{result['edges_imported']} edges in {import_time:.1f}s[/green]"
                )
        except Exception as e:
            console.print(f"[red]Neo4j import failed: {e}[/red]")
            console.print(
                "[yellow]Graph was extracted successfully."
                " Fix Neo4j connection and retry.[/yellow]"
            )
            sys.exit(1)
    finally:
        if cloned_dir and cloned_dir.parent.exists():
            shutil.rmtree(cloned_dir.parent, ignore_errors=True)


@main.command()
@click.option("--neo4j-uri", default="bolt://localhost:7687",
              envvar="ARCHGRAPH_NEO4J_URI", help="Neo4j bolt URI")
@click.option("--neo4j-user", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_USER", help="Neo4j username")
@click.option("--neo4j-password", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_PASSWORD", help="Neo4j password")
@click.option("--neo4j-database", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_DATABASE", help="Neo4j database name")
@click.argument("cypher")
def query(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
    cypher: str,
) -> None:
    """Execute a Cypher query against the graph database."""
    _setup_logging(False)

    try:
        with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
            results = store.query(cypher)
            if not results:
                console.print("[yellow]No results.[/yellow]")
                return

            # Display as table
            keys = list(results[0].keys())
            table = Table()
            for key in keys:
                table.add_column(key, style="cyan")
            for row in results:
                table.add_row(*[str(row.get(k, "")) for k in keys])
            console.print(table)
            console.print(f"\n{len(results)} row(s)")
    except Exception as e:
        console.print(f"[red]Query failed: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="neo4j", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def stats(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
) -> None:
    """Show graph database statistics."""
    _setup_logging(False)

    try:
        with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
            db_stats = store.stats()

            table = Table(title="Graph Statistics")
            table.add_column("Type", style="cyan")
            table.add_column("Count", justify="right", style="green")

            for label, count in sorted(db_stats.get("nodes", {}).items()):
                table.add_row(f"Node: {label}", str(count))
            for etype, count in sorted(db_stats.get("edges", {}).items()):
                table.add_row(f"Edge: {etype}", str(count))

            console.print(table)
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="neo4j", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def schema(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
) -> None:
    """Show the graph database schema."""
    _setup_logging(False)

    try:
        with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
            info = store.schema_info()
            console.print("\n[bold]Node Labels:[/bold]", ", ".join(info["node_labels"]))
            console.print("[bold]Relationship Types:[/bold]", ", ".join(info["relationship_types"]))
            console.print("[bold]Property Keys:[/bold]", ", ".join(info["property_keys"]))
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
