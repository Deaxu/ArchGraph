"""Graph builder — orchestrates all extractors and builds the final graph."""

from __future__ import annotations

import logging
from pathlib import Path

from archgraph.config import ExtractConfig
from archgraph.enrichment.churn import ChurnEnricher
from archgraph.extractors.annotations import AnnotationExtractor
from archgraph.extractors.clang import ClangExtractor
from archgraph.extractors.dependencies import DependencyExtractor
from archgraph.extractors.git import GitExtractor
from archgraph.extractors.security_labels import SecurityLabeler
from archgraph.extractors.treesitter import TreeSitterExtractor
from archgraph.graph.schema import GraphData

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Orchestrates the full extraction pipeline."""

    def __init__(self, config: ExtractConfig) -> None:
        self.config = config

    def build(self) -> GraphData:
        """Run the full extraction pipeline and return the combined graph."""
        graph = GraphData()
        repo = self.config.repo_path
        total_steps = 8

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

        # Step 6: Clang deep analysis (after security labeling, before churn)
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

        # Deduplicate
        graph.deduplicate()
        logger.info(
            "Final graph: %d nodes, %d edges",
            graph.node_count,
            graph.edge_count,
        )

        return graph
