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
from archgraph.manifest import delete_manifest

# Force UTF-8 on Windows to avoid UnicodeDecodeError with cp1254/cp1252 codepages.
# On Linux/macOS UTF-8 is already the default so this is a no-op.
import io as _io
_stderr_safe = _io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
console = Console(stderr=True, file=_stderr_safe)

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
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        console.print(f"[red]git clone failed:[/red] {result.stderr.strip()}")
        raise click.Abort()
    console.print("[green]Clone complete.[/green]")
    return tmp / "repo"


def _setup_logging(verbose: bool) -> None:
    handler = RichHandler(console=console, show_path=False, rich_tracebacks=True)
    handler.setFormatter(logging.Formatter("%(message)s"))

    # Only set archgraph loggers to DEBUG; keep third-party (neo4j, urllib3) at WARNING
    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    root.addHandler(handler)

    ag_logger = logging.getLogger("archgraph")
    ag_logger.setLevel(logging.DEBUG if verbose else logging.INFO)


def _detect_languages(repo_path: Path) -> list[str]:
    """Auto-detect languages by counting file extensions."""
    import os
    from collections import Counter
    from archgraph.config import EXTENSION_MAP, SKIP_DIRS
    ext_counter: Counter[str] = Counter()
    for root, dirs, filenames in os.walk(repo_path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext in EXTENSION_MAP:
                ext_counter[EXTENSION_MAP[ext]] += 1
    detected = [lang for lang, _ in ext_counter.most_common(5)]
    return detected if detected else ["c", "cpp", "rust", "java", "go"]

@click.group()
@click.version_option(package_name="archgraph")
def main() -> None:
    """ArchGraph — Source code graph extraction & Cypher query tool."""
    pass


@main.command()
@click.argument("repo_path")
@click.option(
    "--languages", "-l",
    default="auto",
    help="Languages (auto=detect)",
)
@click.option("--branch", "-b", default=None, help="Branch to clone (for git URLs)")
@click.option("--depth", "-d", type=int, default=None, help="Clone depth (for git URLs)")
@click.option("--neo4j-uri", default="bolt://localhost:7687",
              envvar="ARCHGRAPH_NEO4J_URI", help="Neo4j bolt URI")
@click.option("--neo4j-user", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_USER", help="Neo4j username")
@click.option("--neo4j-password", default="archgraph",
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
@click.option("--include-clustering/--no-clustering", default=False, help="Enable cluster detection")
@click.option("--include-process/--no-process", default=False, help="Enable process tracing")
@click.option("--include-body/--no-body", default=True, help="Store source code bodies in graph nodes")
@click.option("--max-body-size", type=int, default=51_200, help="Max body size in bytes (truncate beyond)")
@click.option("--incremental/--no-incremental", default=False,
              help="Incremental extraction — only re-extract changed files")
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
    incremental: bool,
    include_clustering: bool,
    include_process: bool,
    include_body: bool,
    max_body_size: int,
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
        languages=_detect_languages(resolved_path) if languages == "auto" else [l.strip() for l in languages.split(",")],
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
        incremental=incremental,
        include_clustering=include_clustering,
        include_process=include_process,
        include_body=include_body,
        max_body_size=max_body_size,
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

        # Register repo in global registry
        try:
            from archgraph.registry import get_registry
            registry = get_registry()
            registry.register(
                resolved_path,
                neo4j_uri=neo4j_uri,
                neo4j_database=neo4j_database,
                languages=[l.strip() for l in languages.split(',')],
                stats={'node_count': graph.node_count, 'edge_count': graph.edge_count},
            )
        except Exception as e:
            console.print(f"[dim]Registry update failed: {e}[/dim]")

        # Generate skills if requested
        if include_clustering or include_process:
            try:
                from archgraph.skills import SkillGenerator
                with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
                    store.import_graph(graph)
                    gen = SkillGenerator(store)
                    gen.generate_skills(resolved_path)
                    console.print("[green]Agent skills generated.[/green]")
            except Exception:
                pass

        try:
            from archgraph.registry import get_registry
            get_registry().register(resolved_path, neo4j_uri=neo4j_uri, neo4j_database=neo4j_database,
                stats={"node_count": graph.node_count, "edge_count": graph.edge_count})
        except Exception:
            pass

        # Import into Neo4j
        console.print(f"\n[bold]Importing into Neo4j[/bold] at {neo4j_uri}...")
        try:
            with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
                if clear_db:
                    console.print("[yellow]Clearing existing data...[/yellow]")
                    store.clear()
                    delete_manifest(resolved_path)
                    console.print("[yellow]Manifest cleared.[/yellow]")

                store.create_indexes()
                import_start = time.time()
                result = store.import_graph(graph, use_create=clear_db)
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
@click.option("--neo4j-password", default="archgraph",
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
@click.option("--name", "-n", default="", help="Symbol name (supports * wildcards)")
@click.option("--type", "-t", "sym_type", default="",
              help="Filter by type: function, class, struct, interface, enum, module, file")
@click.option("--file-pattern", "-f", default="", help="File path pattern (supports * wildcards)")
@click.option("--limit", "-l", type=int, default=20, help="Max results")
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def search(
    name: str, sym_type: str, file_pattern: str, limit: int,
    neo4j_uri: str, neo4j_user: str, neo4j_password: str, neo4j_database: str,
) -> None:
    """Search for symbols by name, type, or file pattern."""
    _setup_logging(False)
    if not name and not sym_type and not file_pattern:
        console.print("[red]At least one of --name, --type, or --file-pattern is required.[/red]")
        raise SystemExit(1)
    try:
        from archgraph.api import ArchGraph
        ag = ArchGraph(neo4j_uri, neo4j_user, neo4j_password, neo4j_database)
        results = ag.search(name=name, type=sym_type, file_pattern=file_pattern, limit=limit)
        ag.close()
        if not results:
            console.print("[yellow]No results.[/yellow]")
            return
        table = Table()
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Type")
        table.add_column("File", style="dim")
        table.add_column("Line", justify="right")
        for r in results:
            labels = r.get("labels", [])
            label = [l for l in labels if l != "_Node"][0] if labels else ""
            table.add_row(
                r.get("id", ""), r.get("name", ""), label,
                r.get("file", ""), str(r.get("line", "")),
            )
        console.print(table)
        console.print(f"\n{len(results)} result(s)")
    except Exception as e:
        console.print(f"[red]Search failed: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
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
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
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


@main.command()
@click.argument("repo_path")
@click.option(
    "--languages", "-l",
    default="auto",
    help="Languages (auto=detect)",
)
@click.option("--neo4j-uri", default="bolt://localhost:7687",
              envvar="ARCHGRAPH_NEO4J_URI", help="Neo4j bolt URI")
@click.option("--neo4j-user", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_USER", help="Neo4j username")
@click.option("--neo4j-password", default="archgraph",
              envvar="ARCHGRAPH_NEO4J_PASSWORD", help="Neo4j password")
@click.option("--neo4j-database", default="neo4j",
              envvar="ARCHGRAPH_NEO4J_DATABASE", help="Neo4j database name")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
def diff(
    repo_path: str,
    languages: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
    verbose: bool,
) -> None:
    """Show differences between the current repo state and the stored graph.

    Extracts the current repo state and compares it with the graph stored
    in Neo4j to show added, removed, and modified nodes/edges.
    """
    _setup_logging(verbose)

    resolved_path = Path(repo_path)
    if not resolved_path.is_dir():
        console.print(f"[red]Not a directory: {repo_path}[/red]")
        raise SystemExit(1)
    resolved_path = resolved_path.resolve()

    config = ExtractConfig(
        repo_path=resolved_path,
        languages=_detect_languages(resolved_path) if languages == "auto" else [l.strip() for l in languages.split(",")],
        include_git=True,
        include_deps=True,
        include_annotations=True,
        include_security_labels=True,
    )

    console.print(f"\n[bold]ArchGraph Diff[/bold] — [cyan]{resolved_path}[/cyan]\n")

    # Step 1: Extract current state
    console.print("[bold]Extracting current repo state...[/bold]")
    builder = GraphBuilder(config)
    current_graph = builder.build()
    console.print(
        f"  Current: {current_graph.node_count} nodes, {current_graph.edge_count} edges"
    )

    # Step 2: Load stored graph from Neo4j
    console.print("[bold]Loading stored graph from Neo4j...[/bold]")
    try:
        with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
            stored_graph = store.load_graph()
    except Exception as e:
        console.print(f"[red]Failed to load graph from Neo4j: {e}[/red]")
        sys.exit(1)

    console.print(
        f"  Stored:  {stored_graph.node_count} nodes, {stored_graph.edge_count} edges"
    )

    # Step 3: Compute diff
    graph_diff = stored_graph.diff(current_graph)

    if not graph_diff.has_changes:
        console.print("\n[green]No changes detected.[/green]")
        return

    # Step 4: Display results
    summary = graph_diff.summary()
    table = Table(title="Graph Diff Summary")
    table.add_column("Change Type", style="cyan")
    table.add_column("Count", justify="right", style="green")

    for key, count in summary.items():
        style = "green" if count == 0 else "yellow"
        table.add_row(key.replace("_", " ").title(), f"[{style}]{count}[/{style}]")

    console.print(table)

    # Show details if there are changes
    if graph_diff.nodes_added:
        console.print(f"\n[green]+ Added Nodes ({len(graph_diff.nodes_added)}):[/green]")
        for node in graph_diff.nodes_added[:20]:
            console.print(f"  + [{node.label}] {node.id}")
        if len(graph_diff.nodes_added) > 20:
            console.print(f"  ... and {len(graph_diff.nodes_added) - 20} more")

    if graph_diff.nodes_removed:
        console.print(f"\n[red]- Removed Nodes ({len(graph_diff.nodes_removed)}):[/red]")
        for node in graph_diff.nodes_removed[:20]:
            console.print(f"  - [{node.label}] {node.id}")
        if len(graph_diff.nodes_removed) > 20:
            console.print(f"  ... and {len(graph_diff.nodes_removed) - 20} more")

    if graph_diff.nodes_modified:
        console.print(f"\n[yellow]~ Modified Nodes ({len(graph_diff.nodes_modified)}):[/yellow]")
        for change in graph_diff.nodes_modified[:20]:
            props = ", ".join(
                f"{k}: {old}→{new}" for k, (old, new) in change.changed_properties.items()
            )
            console.print(f"  ~ [{change.label}] {change.node_id}: {props}")
        if len(graph_diff.nodes_modified) > 20:
            console.print(f"  ... and {len(graph_diff.nodes_modified) - 20} more")




# ── MCP Server Command ──────────────────────────────────────────────────────

@main.command()
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def mcp(
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
) -> None:
    """Start MCP server for AI agent integration."""
    import asyncio
    from archgraph.mcp.server import run_mcp_server

    _setup_logging(False)
    console.print("[bold]Starting ArchGraph MCP server...[/bold]")
    console.print("Connect via: claude mcp add archgraph -- archgraph mcp")
    asyncio.run(run_mcp_server(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
        neo4j_database=neo4j_database,
    ))


# ── Web Dashboard Command ───────────────────────────────────────────────────

@main.command()
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.option("--port", "-p", default=8080, help="Bind port")
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def serve(
    host: str,
    port: int,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
) -> None:
    """Start web dashboard for interactive graph exploration."""
    from archgraph.server.web import run_server

    _setup_logging(False)
    console.print(f"[bold]Starting ArchGraph dashboard at http://{host}:{port}[/bold]")
    run_server(
        host=host,
        port=port,
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=neo4j_password,
        neo4j_database=neo4j_database,
    )


# ── Skills Generation Command ───────────────────────────────────────────────

@main.command()
@click.argument("repo_path")
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def skills(
    repo_path: str,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
) -> None:
    """Generate AI agent skill files based on graph analysis."""
    from archgraph.graph.neo4j_store import Neo4jStore
    from archgraph.skills import SkillGenerator

    _setup_logging(False)
    resolved_path = Path(repo_path).resolve()

    console.print(f"[bold]Generating skills for[/bold] [cyan]{resolved_path}[/cyan]...")

    try:
        with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
            generator = SkillGenerator(store)
            generated_paths = generator.generate_skills(resolved_path)

            table = Table(title="Generated Skills")
            table.add_column("File", style="cyan")
            for p in generated_paths:
                table.add_row(str(p.relative_to(resolved_path)))
            console.print(table)
            console.print(f"\n[green]{len(generated_paths)} skill files generated.[/green]")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        sys.exit(1)


# ── Registry Command ────────────────────────────────────────────────────────

@main.command()
@click.option("--format", "output_format", default="table", type=click.Choice(["table", "json"]))
def repos(output_format: str) -> None:
    """List all registered repositories."""
    import json as json_mod
    from archgraph.registry import get_registry

    _setup_logging(False)
    registry = get_registry()
    entries = registry.list_repos()

    if not entries:
        console.print("[yellow]No repositories registered.[/yellow]")
        console.print("Run [bold]archgraph extract[/bold] to index a repo.")
        return

    if output_format == "json":
        console.print(json_mod.dumps([e.to_dict() for e in entries], indent=2))
    else:
        table = Table(title="Registered Repositories")
        table.add_column("Name", style="cyan")
        table.add_column("Path", style="green")
        table.add_column("Languages", style="yellow")
        table.add_column("Nodes", justify="right")
        table.add_column("Edges", justify="right")
        table.add_column("Indexed", style="dim")
        for e in entries:
            table.add_row(
                e.name,
                e.path[:50] + "..." if len(e.path) > 50 else e.path,
                ", ".join(e.languages[:3]) if e.languages else "-",
                str(e.node_count),
                str(e.edge_count),
                e.indexed_at[:10] if e.indexed_at else "-",
            )
        console.print(table)


# ── Impact Analysis Command ─────────────────────────────────────────────────

@main.command("impact")
@click.argument("symbol_id")
@click.option("--direction", "-d", default="upstream", type=click.Choice(["upstream", "downstream", "both"]))
@click.option("--depth", default=5, help="Max traversal depth")
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def _impact(
    symbol_id: str,
    direction: str,
    depth: int,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    neo4j_database: str,
) -> None:
    """Analyze blast radius of a function symbol."""
    from archgraph.graph.neo4j_store import Neo4jStore
    from archgraph.tool.impact import ImpactAnalyzer

    _setup_logging(False)

    try:
        with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
            analyzer = ImpactAnalyzer(store)
            result = analyzer.analyze_impact(symbol_id, direction, depth)

            console.print(f"\n[bold]Impact Analysis[/bold] — [cyan]{symbol_id}[/cyan]")
            res_conf = result.get("resolution_confidence", "unknown")
            stats = result.get("resolution_stats", {})
            console.print(
                f"Direction: {direction} | Resolution: {res_conf} "
                f"(scip:{stats.get('scip_edges', 0)} heuristic:{stats.get('heuristic_edges', 0)})"
            )

            if result["immediate"]:
                console.print(f"\n[green]Immediate (depth 1):[/green]")
                for item in result["immediate"][:10]:
                    console.print(f"  -> {item['name']} ({item.get('file', '')})")

            if result["downstream"]:
                console.print(f"\n[yellow]Downstream (depth 2):[/yellow]")
                for item in result["downstream"][:10]:
                    console.print(f"  -> {item['name']} ({item.get('file', '')})")

            if result["transitive"]:
                console.print(f"\n[dim]Transitive (depth 3+):[/dim]")
                for item in result["transitive"][:10]:
                    console.print(f"  -> {item['name']} ({item.get('file', '')})")

            if result["security_flags"]:
                console.print(f"\n[red]Warning - Security flags:[/red]")
                for flag in result["security_flags"]:
                    console.print(f"  !! {flag}")

            console.print(f"\nTotal affected: {result['total_affected']}")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        sys.exit(1)



@main.command()
@click.argument("repo_path")
@click.option("--format", "export_format", default="json", type=click.Choice(["json", "graphml", "csv"]))
@click.option("--output", "-o", default=None, help="Output path")
@click.option("--from-repo", "from_repo", is_flag=True, default=False,
              help="Re-extract from repo instead of reading from Neo4j")
@click.option("--languages", "-l", default="auto", help="Languages (only with --from-repo)")
@click.option("-w", "--workers", type=int, default=0, help="Workers (only with --from-repo)")
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def export(repo_path, export_format, output, from_repo, languages, workers,
           neo4j_uri, neo4j_user, neo4j_password, neo4j_database):
    """Export graph to JSON, GraphML, or CSV.

    By default reads the graph from Neo4j. Use --from-repo to re-extract from source.
    """
    from archgraph.export import export_json, export_graphml, export_csv
    _setup_logging(False)
    resolved_path = Path(repo_path).resolve()

    if from_repo:
        if not resolved_path.is_dir():
            console.print(f"[red]Not a directory: {repo_path}[/red]")
            raise SystemExit(1)
        langs = _detect_languages(resolved_path) if languages == "auto" else [l.strip() for l in languages.split(",")]
        config = ExtractConfig(repo_path=resolved_path, languages=langs, workers=workers)
        console.print("[bold]Extracting graph from repo...[/bold]")
        graph = GraphBuilder(config).build()
    else:
        console.print("[bold]Loading graph from Neo4j...[/bold]")
        try:
            with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
                graph = store.load_graph()
        except Exception as e:
            console.print(f"[red]Failed to load from Neo4j: {e}[/red]")
            console.print("[dim]Hint: use --from-repo to extract directly from source[/dim]")
            raise SystemExit(1)

    console.print(f"  -> {graph.node_count} nodes, {graph.edge_count} edges")

    if export_format == "json":
        out = Path(output) if output else resolved_path / "archgraph_export.json"
        export_json(graph, out)
    elif export_format == "graphml":
        out = Path(output) if output else resolved_path / "archgraph_export.graphml"
        export_graphml(graph, out)
    else:
        out = Path(output) if output else resolved_path / "archgraph_export"
        export_csv(graph, out)
    console.print(f"[green]Exported to {out}[/green]")


@main.command()
@click.argument("repo_path")
@click.option("--output", "-o", default=None, help="Output HTML path")
@click.option("--neo4j-uri", default="bolt://localhost:7687", envvar="ARCHGRAPH_NEO4J_URI")
@click.option("--neo4j-user", default="neo4j", envvar="ARCHGRAPH_NEO4J_USER")
@click.option("--neo4j-password", default="archgraph", envvar="ARCHGRAPH_NEO4J_PASSWORD")
@click.option("--neo4j-database", default="neo4j", envvar="ARCHGRAPH_NEO4J_DATABASE")
def report(repo_path, output, neo4j_uri, neo4j_user, neo4j_password, neo4j_database):
    """Generate HTML security report."""
    from archgraph.report import generate_report
    _setup_logging(False)
    resolved_path = Path(repo_path).resolve()
    try:
        with Neo4jStore(neo4j_uri, neo4j_user, neo4j_password, neo4j_database) as store:
            path = generate_report(store, resolved_path, Path(output) if output else None)
            console.print(f"[green]Report: {path}[/green]")
    except Exception as e:
        console.print(f"[red]Failed: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
