"""Graph builder — orchestrates all extractors and builds the final graph."""

from __future__ import annotations

import logging
import os
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

from archgraph.config import ExtractConfig
from archgraph.enrichment.churn import ChurnEnricher
from archgraph.enrichment.cve import CveEnricher
from archgraph.extractors.annotations import AnnotationExtractor
from archgraph.extractors.clang import ClangExtractor
from archgraph.extractors.dependencies import DependencyExtractor
from archgraph.extractors.git import GitExtractor
from archgraph.extractors.security_labels import SecurityLabeler
from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import GraphData

logger = logging.getLogger(__name__)


def _resolve_workers(config_workers: int) -> int:
    """Resolve worker count: 0=auto, 1=sequential, N=explicit."""
    if config_workers == 0:
        return min(os.cpu_count() or 1, 8)
    return config_workers


class GraphBuilder:
    """Orchestrates the full extraction pipeline."""

    def __init__(self, config: ExtractConfig) -> None:
        self.config = config

    def build(self) -> GraphData:
        """Run the full extraction pipeline and return the combined graph."""
        workers = _resolve_workers(self.config.workers)

        if workers > 1:
            return self._build_parallel(workers)
        return self._build_sequential()

    # ── Sequential pipeline (workers=1) ─────────────────────────────────

    def _build_sequential(self) -> GraphData:
        """Original sequential pipeline — guaranteed identical output."""
        graph = GraphData()
        repo = self.config.repo_path
        total_steps = 9

        # Step 1: Tree-sitter structural extraction
        logger.info("Step 1/%d: Tree-sitter extraction", total_steps)
        ts_extractor = TreeSitterExtractor(languages=self.config.languages)
        ts_graph = ts_extractor.extract(repo)
        graph.merge(ts_graph)
        logger.info(
            "  -> %d nodes, %d edges from tree-sitter",
            ts_graph.node_count,
            ts_graph.edge_count,
        )

        # Step 2: Git history
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

        # Step 5: Security labeling
        if self.config.include_security_labels:
            logger.info("Step 5/%d: Security labeling", total_steps)
            labeler = SecurityLabeler()
            count = labeler.label(graph)
            logger.info("  -> %d functions labeled", count)
        else:
            logger.info("Step 5/%d: Security labeling (skipped)", total_steps)

        # Step 6: Clang deep analysis
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
        if self.config.include_git:
            logger.info("Step 8/%d: Churn enrichment", total_steps)
            enricher = ChurnEnricher()
            count = enricher.enrich(graph, repo)
            logger.info("  -> %d files enriched with churn data", count)
        else:
            logger.info("Step 8/%d: Churn enrichment (skipped)", total_steps)

        # Step 9: CVE enrichment
        if self.config.include_cve:
            logger.info("Step 9/%d: CVE enrichment", total_steps)
            cve_enricher = CveEnricher(batch_size=self.config.osv_batch_size)
            vuln_count = cve_enricher.enrich(graph)
            logger.info("  -> %d vulnerabilities found", vuln_count)
        else:
            logger.info("Step 9/%d: CVE enrichment (skipped)", total_steps)

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
        total_steps = 9
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
        ts_extractor = TreeSitterExtractor(languages=self.config.languages)
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
