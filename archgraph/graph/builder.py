"""Graph builder — orchestrates all extractors and builds the final graph."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from archgraph.config import ExtractConfig
from archgraph.enrichment.churn import ChurnEnricher
from archgraph.enrichment.cve import CveEnricher
from archgraph.enrichment.clustering import ClusterEnricher
from archgraph.enrichment.process import ProcessTracer
from archgraph.extractors.annotations import AnnotationExtractor
from archgraph.extractors.clang import ClangExtractor
from archgraph.extractors.dependencies import DependencyExtractor
from archgraph.extractors.git import GitExtractor
from archgraph.extractors.scip_resolver import ScipResolver
from archgraph.extractors.security_labels import SecurityLabeler
from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import GraphData
from archgraph.manifest import (
    ChangeSet,
    build_manifest_from_files,
    compute_changeset,
    compute_dependencies_hash,
    get_git_head,
    load_manifest,
    save_manifest,
    scan_current_files,
)

logger = logging.getLogger(__name__)


def _resolve_workers(config_workers: int) -> int:
    """Resolve worker count: 0=auto, 1=sequential, N=explicit."""
    if config_workers == 0:
        return min(os.cpu_count() or 1, 8)
    return config_workers


class GraphBuilder:
    """Orchestrates the full extraction pipeline."""

    def __init__(
        self,
        config: ExtractConfig,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> None:
        self.config = config
        self._progress = progress_callback or (lambda step, total, msg: None)

    def build(self) -> GraphData:
        """Run the extraction pipeline and return the combined graph."""
        workers = _resolve_workers(self.config.workers)

        if self.config.incremental:
            return self._build_incremental(workers)

        graph = self._build_full(workers)
        # Save manifest after full build so next incremental can use it
        self._save_current_manifest()
        return graph

    # ── Full build dispatch ────────────────────────────────────────────────

    def _build_full(self, workers: int) -> GraphData:
        if workers > 1:
            return self._build_parallel(workers)
        return self._build_sequential()

    # ── Incremental pipeline ───────────────────────────────────────────────

    def _build_incremental(self, workers: int) -> GraphData:
        """Incremental extraction — only re-extract changed files."""
        repo = self.config.repo_path
        old_manifest = load_manifest(repo)

        if old_manifest is None:
            logger.info("No previous manifest found, running full extraction")
            graph = self._build_full(workers)
            self._save_current_manifest()
            return graph

        # Scan current state
        current_files = scan_current_files(repo)
        current_head = get_git_head(repo)
        current_deps_hash = compute_dependencies_hash(repo) if self.config.include_deps else ""

        changeset = compute_changeset(
            old_manifest, current_files,
            current_git_head=current_head,
            current_deps_hash=current_deps_hash,
        )

        if not changeset.has_changes and changeset.git_head_old == current_head:
            logger.info("No changes detected, returning empty graph")
            return GraphData()

        # If git history diverged (old head not ancestor of new), fall back to full
        if (
            changeset.git_head_old
            and current_head
            and changeset.git_head_old != current_head
            and not self._is_ancestor(repo, changeset.git_head_old, current_head)
        ):
            logger.info("Git history diverged, falling back to full extraction")
            graph = self._build_full(workers)
            self._save_current_manifest()
            return graph

        logger.info(
            "Incremental: %d added, %d modified, %d deleted, deps_changed=%s",
            len(changeset.added_files),
            len(changeset.modified_files),
            len(changeset.deleted_files),
            changeset.deps_changed,
        )

        graph = self._run_incremental_steps(changeset, workers)

        # Save updated manifest
        self._save_current_manifest()
        return graph

    def _run_incremental_steps(self, changeset: ChangeSet, workers: int) -> GraphData:
        """Execute incremental extraction steps based on the changeset."""
        graph = GraphData()
        repo = self.config.repo_path
        changed = changeset.changed_files

        # Step 1: Tree-sitter — only changed files
        if changed:
            logger.info("Incremental tree-sitter: %d files", len(changed))
            ts_ext = TreeSitterExtractor(
                languages=self.config.languages,
                include_body=self.config.include_body,
                max_body_size=self.config.max_body_size,
            )
            ts_graph = ts_ext.extract(repo, workers=workers, changed_files=changed)
            graph.merge(ts_graph)

        # Step 2: Git — only new commits since old head
        if self.config.include_git and changeset.git_head_old:
            logger.info("Incremental git: since %s", changeset.git_head_old[:12])
            git_ext = GitExtractor(max_commits=self.config.git_max_commits)
            git_graph = git_ext.extract(repo, since_commit=changeset.git_head_old)
            graph.merge(git_graph)

        # Step 3: Dependencies — only if manifests changed
        if self.config.include_deps and changeset.deps_changed:
            logger.info("Incremental deps: manifest files changed")
            dep_ext = DependencyExtractor()
            dep_graph = dep_ext.extract(repo)
            graph.merge(dep_graph)

        # Step 4: Annotations — full scan (cheap operation)
        if self.config.include_annotations and changed:
            ann_ext = AnnotationExtractor()
            ann_graph = ann_ext.extract(repo)
            graph.merge(ann_graph)

        # Step 4.5: Call resolution (SCIP + heuristic fallback)
        if self.config.include_scip:
            logger.info("Incremental call resolution")
            ScipResolver(graph, repo, self.config.languages).resolve()
        else:
            logger.info("Incremental call resolution (SCIP skipped)")
            from archgraph.extractors.call_resolver import CallResolver
            CallResolver(graph).resolve()

        # Step 5: Security labeling — on current graph
        if self.config.include_security_labels:
            labeler = SecurityLabeler()
            labeler.label(graph)

        # Step 6: Clang deep — changed files only
        if self.config.include_clang and changed:
            clang_ext = ClangExtractor(
                compile_commands=self.config.clang_compile_commands,
                extra_args=self.config.clang_extra_args,
            )
            if clang_ext.available:
                clang_graph = clang_ext.extract(repo, workers=workers)
                graph.merge(clang_graph)

        # Step 7: Deep analysis — changed files only
        if self.config.include_deep and changed:
            from archgraph.extractors.deep import TreeSitterDeepExtractor

            deep_ext = TreeSitterDeepExtractor(languages=self.config.languages)
            if deep_ext.available_languages:
                deep_graph = deep_ext.extract(repo, workers=workers)
                graph.merge(deep_graph)

        # Step 8: Churn enrichment
        if self.config.include_git:
            enricher = ChurnEnricher()
            enricher.enrich(graph, repo)

        # Step 9: CVE enrichment
        if self.config.include_cve:
            cve_enricher = CveEnricher(batch_size=self.config.osv_batch_size)
            cve_enricher.enrich(graph)

        graph.deduplicate()
        logger.info(
            "Incremental graph: %d nodes, %d edges",
            graph.node_count, graph.edge_count,
        )
        return graph

    def _save_current_manifest(self) -> None:
        """Scan current files and save manifest."""
        repo = self.config.repo_path
        current_files = scan_current_files(repo)
        git_head = get_git_head(repo)
        deps_hash = compute_dependencies_hash(repo) if self.config.include_deps else ""
        manifest = build_manifest_from_files(repo, current_files, git_head, deps_hash)
        save_manifest(repo, manifest)

    @staticmethod
    def _is_ancestor(repo: Path, ancestor: str, descendant: str) -> bool:
        """Check if ancestor commit is an ancestor of descendant."""
        import subprocess

        try:
            result = subprocess.run(
                ["git", "-C", str(repo), "merge-base", "--is-ancestor", ancestor, descendant],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    # ── Sequential pipeline (workers=1) ─────────────────────────────────

    def _build_sequential(self) -> GraphData:
        """Original sequential pipeline — guaranteed identical output."""
        graph = GraphData()
        repo = self.config.repo_path
        total_steps = 11

        # Step 1: Tree-sitter structural extraction
        self._progress(1, total_steps, "Tree-sitter extraction")
        logger.info("Step 1/%d: Tree-sitter extraction", total_steps)
        ts_extractor = TreeSitterExtractor(
            languages=self.config.languages,
            include_body=self.config.include_body,
            max_body_size=self.config.max_body_size,
        )
        ts_graph = ts_extractor.extract(repo)
        graph.merge(ts_graph)
        logger.info(
            "  -> %d nodes, %d edges from tree-sitter",
            ts_graph.node_count,
            ts_graph.edge_count,
        )

        # Step 2: Git history
        self._progress(2, total_steps, "Git extraction")
        if self.config.include_git:
            logger.info("Step 2/%d: Git extraction", total_steps)
            git_extractor = GitExtractor(max_commits=self.config.git_max_commits)
            git_graph = git_extractor.extract(repo)
            graph.merge(git_graph)
            logger.info(
                "  -> %d nodes, %d edges from git",
                git_graph.node_count,
                git_graph.edge_count,
            )
        else:
            logger.info("Step 2/%d: Git extraction (skipped)", total_steps)

        # Step 3: Dependencies
        self._progress(3, total_steps, "Dependency extraction")
        if self.config.include_deps:
            logger.info("Step 3/%d: Dependency extraction", total_steps)
            dep_extractor = DependencyExtractor()
            dep_graph = dep_extractor.extract(repo)
            graph.merge(dep_graph)
            logger.info(
                "  -> %d nodes, %d edges from dependencies",
                dep_graph.node_count,
                dep_graph.edge_count,
            )
        else:
            logger.info("Step 3/%d: Dependency extraction (skipped)", total_steps)

        # Step 4: Annotations
        self._progress(4, total_steps, "Annotation extraction")
        if self.config.include_annotations:
            logger.info("Step 4/%d: Annotation extraction", total_steps)
            ann_extractor = AnnotationExtractor()
            ann_graph = ann_extractor.extract(repo)
            graph.merge(ann_graph)
            logger.info(
                "  -> %d nodes, %d edges from annotations",
                ann_graph.node_count,
                ann_graph.edge_count,
            )
        else:
            logger.info("Step 4/%d: Annotation extraction (skipped)", total_steps)

        # Step 4.5: Call resolution (SCIP + heuristic fallback)
        self._progress(5, total_steps, "Call resolution (SCIP)" if self.config.include_scip else "Call resolution (heuristic)")
        if self.config.include_scip:
            logger.info("Step 4.5/%d: Call resolution (SCIP + heuristic)", total_steps)
            ScipResolver(graph, repo, self.config.languages).resolve()
        else:
            logger.info("Step 4.5/%d: Call resolution (heuristic only)", total_steps)
            from archgraph.extractors.call_resolver import CallResolver
            CallResolver(graph).resolve()

        # Step 5: Security labeling
        self._progress(6, total_steps, "Security labeling")
        if self.config.include_security_labels:
            logger.info("Step 5/%d: Security labeling", total_steps)
            labeler = SecurityLabeler()
            count = labeler.label(graph)
            logger.info("  -> %d functions labeled", count)
        else:
            logger.info("Step 5/%d: Security labeling (skipped)", total_steps)

        # Step 6: Clang deep analysis
        self._progress(7, total_steps, "Clang deep analysis")
        if self.config.include_clang:
            clang_ext = ClangExtractor(
                compile_commands=self.config.clang_compile_commands,
                extra_args=self.config.clang_extra_args,
            )
            if clang_ext.available:
                logger.info("Step 6/%d: Clang deep analysis", total_steps)
                clang_graph = clang_ext.extract(repo)
                graph.merge(clang_graph)
                logger.info(
                    "  -> %d nodes, %d edges from clang",
                    clang_graph.node_count,
                    clang_graph.edge_count,
                )
            else:
                logger.info(
                    "Step 6/%d: Clang deep analysis (skipped — libclang not installed)",
                    total_steps,
                )
        else:
            logger.info("Step 6/%d: Clang deep analysis (skipped)", total_steps)

        # Step 7: Tree-sitter deep analysis (Rust, Java, Go, Kotlin, Swift)
        self._progress(8, total_steps, "Tree-sitter deep analysis")
        if self.config.include_deep:
            from archgraph.extractors.deep import TreeSitterDeepExtractor

            deep_ext = TreeSitterDeepExtractor(languages=self.config.languages)
            if deep_ext.available_languages:
                logger.info(
                    "Step 7/%d: Tree-sitter deep analysis (%s)",
                    total_steps,
                    ", ".join(deep_ext.available_languages),
                )
                deep_graph = deep_ext.extract(repo)
                graph.merge(deep_graph)
                logger.info(
                    "  -> %d nodes, %d edges from deep analysis",
                    deep_graph.node_count,
                    deep_graph.edge_count,
                )
            else:
                logger.info(
                    "Step 7/%d: Tree-sitter deep analysis (skipped — no languages available)",
                    total_steps,
                )
        else:
            logger.info("Step 7/%d: Tree-sitter deep analysis (skipped)", total_steps)

        # Step 8: Churn enrichment
        self._progress(9, total_steps, "Churn enrichment")
        if self.config.include_git:
            logger.info("Step 8/%d: Churn enrichment", total_steps)
            enricher = ChurnEnricher()
            count = enricher.enrich(graph, repo)
            logger.info("  -> %d files enriched with churn data", count)
        else:
            logger.info("Step 8/%d: Churn enrichment (skipped)", total_steps)

        # Step 9: CVE enrichment
        self._progress(10, total_steps, "CVE enrichment")
        if self.config.include_cve:
            logger.info("Step 9/%d: CVE enrichment", total_steps)
            cve_enricher = CveEnricher(batch_size=self.config.osv_batch_size)
            vuln_count = cve_enricher.enrich(graph)
            logger.info("  -> %d vulnerabilities found", vuln_count)
        else:
            logger.info("Step 9/%d: CVE enrichment (skipped)", total_steps)

        # Step 10: Clustering
        self._progress(11, total_steps, "Clustering")
        if self.config.include_clustering:
            logger.info("Step 10/%d: Clustering", total_steps)
            cluster_enricher = ClusterEnricher()
            cluster_count = cluster_enricher.enrich(graph)
            logger.info("  -> %d clusters detected", cluster_count)
        else:
            logger.info("Step 10/%d: Clustering (skipped)", total_steps)

        # Step 11: Process tracing
        self._progress(12, total_steps, "Process tracing")
        if self.config.include_process:
            logger.info("Step 11/%d: Process tracing", total_steps)
            process_tracer = ProcessTracer()
            process_count = process_tracer.enrich(graph)
            logger.info("  -> %d processes traced", process_count)
        else:
            logger.info("Step 11/%d: Process tracing (skipped)", total_steps)

        # Deduplicate
        graph.deduplicate()
        logger.info(
            "Final graph: %d nodes, %d edges",
            graph.node_count,
            graph.edge_count,
        )

        return graph

    # ── Parallel pipeline (workers>1) ───────────────────────────────────

    def _build_parallel(self, workers: int) -> GraphData:
        """Parallel pipeline using ThreadPoolExecutor for step-level concurrency."""
        graph = GraphData()
        repo = self.config.repo_path
        total_steps = 11
        logger.info("Parallel pipeline with %d workers", workers)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            # Group A (concurrent): Steps 1-4
            ts_future = pool.submit(self._step_treesitter, repo, workers)
            git_future: Future[GraphData] | None = None
            if self.config.include_git:
                git_future = pool.submit(self._step_git, repo)
            dep_future: Future[GraphData] | None = None
            if self.config.include_deps:
                dep_future = pool.submit(self._step_deps, repo)
            ann_future: Future[GraphData] | None = None
            if self.config.include_annotations:
                ann_future = pool.submit(self._step_annotations, repo)

            # Merge Group A results
            ts_graph = ts_future.result()
            logger.info(
                "Step 1/%d: Tree-sitter -> %d nodes, %d edges",
                total_steps, ts_graph.node_count, ts_graph.edge_count,
            )
            graph.merge(ts_graph)

            if git_future:
                git_graph = git_future.result()
                logger.info(
                    "Step 2/%d: Git -> %d nodes, %d edges",
                    total_steps, git_graph.node_count, git_graph.edge_count,
                )
                graph.merge(git_graph)
            else:
                logger.info("Step 2/%d: Git extraction (skipped)", total_steps)

            dep_graph: GraphData | None = None
            if dep_future:
                dep_graph = dep_future.result()
                logger.info(
                    "Step 3/%d: Dependencies -> %d nodes, %d edges",
                    total_steps, dep_graph.node_count, dep_graph.edge_count,
                )
                graph.merge(dep_graph)
            else:
                logger.info("Step 3/%d: Dependency extraction (skipped)", total_steps)

            if ann_future:
                ann_graph = ann_future.result()
                logger.info(
                    "Step 4/%d: Annotations -> %d nodes, %d edges",
                    total_steps, ann_graph.node_count, ann_graph.edge_count,
                )
                graph.merge(ann_graph)
            else:
                logger.info("Step 4/%d: Annotation extraction (skipped)", total_steps)

            # Step 4.5: Call resolution (SCIP + heuristic fallback)
            if self.config.include_scip:
                logger.info("Step 4.5/%d: Call resolution (SCIP + heuristic)", total_steps)
                ScipResolver(graph, repo, self.config.languages).resolve()
            else:
                logger.info("Step 4.5/%d: Call resolution (heuristic only)", total_steps)
                from archgraph.extractors.call_resolver import CallResolver
                CallResolver(graph).resolve()

            # Step 5: Security labeling (needs merged graph with functions)
            if self.config.include_security_labels:
                logger.info("Step 5/%d: Security labeling", total_steps)
                labeler = SecurityLabeler()
                count = labeler.label(graph)
                logger.info("  -> %d functions labeled", count)
            else:
                logger.info("Step 5/%d: Security labeling (skipped)", total_steps)

            # Group C (concurrent): Steps 6-7 (depend on Step 1 done)
            clang_future: Future[GraphData] | None = None
            if self.config.include_clang:
                clang_ext = ClangExtractor(
                    compile_commands=self.config.clang_compile_commands,
                    extra_args=self.config.clang_extra_args,
                )
                if clang_ext.available:
                    clang_future = pool.submit(self._step_clang, clang_ext, repo, workers)

            deep_future: Future[GraphData] | None = None
            if self.config.include_deep:
                deep_future = pool.submit(self._step_deep, repo, workers)

            # Step 9: CVE enrichment (depends on Step 3 — dep_graph)
            cve_future: Future[int] | None = None
            if self.config.include_cve and dep_graph:
                cve_future = pool.submit(
                    self._step_cve, graph, self.config.osv_batch_size
                )

            if clang_future:
                clang_graph = clang_future.result()
                logger.info(
                    "Step 6/%d: Clang -> %d nodes, %d edges",
                    total_steps, clang_graph.node_count, clang_graph.edge_count,
                )
                graph.merge(clang_graph)
            else:
                logger.info("Step 6/%d: Clang deep analysis (skipped)", total_steps)

            if deep_future:
                deep_graph = deep_future.result()
                logger.info(
                    "Step 7/%d: Deep -> %d nodes, %d edges",
                    total_steps, deep_graph.node_count, deep_graph.edge_count,
                )
                graph.merge(deep_graph)
            else:
                logger.info("Step 7/%d: Tree-sitter deep analysis (skipped)", total_steps)

            # Step 8: Churn enrichment (needs graph + git done)
            if self.config.include_git:
                logger.info("Step 8/%d: Churn enrichment", total_steps)
                churn_enricher = ChurnEnricher()
                count = churn_enricher.enrich(graph, repo)
                logger.info("  -> %d files enriched with churn data", count)
            else:
                logger.info("Step 8/%d: Churn enrichment (skipped)", total_steps)

            if cve_future:
                vuln_count = cve_future.result()
                logger.info("Step 9/%d: CVE -> %d vulnerabilities", total_steps, vuln_count)
            else:
                logger.info("Step 9/%d: CVE enrichment (skipped)", total_steps)

            # Step 10: Clustering
            if self.config.include_clustering:
                logger.info("Step 10/%d: Clustering", total_steps)
                cluster_enricher = ClusterEnricher()
                cluster_count = cluster_enricher.enrich(graph)
                logger.info("  -> %d clusters detected", cluster_count)
            else:
                logger.info("Step 10/%d: Clustering (skipped)", total_steps)

            # Step 11: Process tracing
            if self.config.include_process:
                logger.info("Step 11/%d: Process tracing", total_steps)
                process_tracer = ProcessTracer()
                process_count = process_tracer.enrich(graph)
                logger.info("  -> %d processes traced", process_count)
            else:
                logger.info("Step 11/%d: Process tracing (skipped)", total_steps)

        # Deduplicate
        graph.deduplicate()
        logger.info(
            "Final graph: %d nodes, %d edges",
            graph.node_count,
            graph.edge_count,
        )

        return graph

    # ── Step methods (each returns its own GraphData) ───────────────────

    def _step_treesitter(self, repo: Path, workers: int) -> GraphData:
        ts_extractor = TreeSitterExtractor(
            languages=self.config.languages,
            include_body=self.config.include_body,
            max_body_size=self.config.max_body_size,
        )
        return ts_extractor.extract(repo, workers=workers)

    def _step_git(self, repo: Path) -> GraphData:
        git_extractor = GitExtractor(max_commits=self.config.git_max_commits)
        return git_extractor.extract(repo)

    def _step_deps(self, repo: Path) -> GraphData:
        dep_extractor = DependencyExtractor()
        return dep_extractor.extract(repo)

    def _step_annotations(self, repo: Path) -> GraphData:
        ann_extractor = AnnotationExtractor()
        return ann_extractor.extract(repo)

    def _step_clang(
        self, clang_ext: ClangExtractor, repo: Path, workers: int
    ) -> GraphData:
        return clang_ext.extract(repo, workers=workers)

    def _step_deep(self, repo: Path, workers: int) -> GraphData:
        from archgraph.extractors.deep import TreeSitterDeepExtractor

        deep_ext = TreeSitterDeepExtractor(languages=self.config.languages)
        if not deep_ext.available_languages:
            return GraphData()
        return deep_ext.extract(repo, workers=workers)

    def _step_cve(self, graph: GraphData, batch_size: int) -> int:
        cve_enricher = CveEnricher(batch_size=batch_size)
        return cve_enricher.enrich(graph)
