"""Tree-sitter deep analysis extractor for Rust, Java, Kotlin, Go, Swift.

Provides intra-procedural CFG, data flow, and taint analysis using tree-sitter
AST, extending the same capabilities that ClangExtractor provides for C/C++.
"""

from __future__ import annotations

import importlib
import logging
import os
from pathlib import Path

import tree_sitter as ts

from archgraph.config import SKIP_DIRS, SKIP_FILES
from archgraph.extractors.base import BaseExtractor
from archgraph.extractors.deep.engine import analyze_function
from archgraph.extractors.deep.lang_spec import REGISTRY, LangSpec
from archgraph.graph.schema import GraphData

# Import language specs to trigger registration
from archgraph.extractors.deep import rust as _rust  # noqa: F401
from archgraph.extractors.deep import java as _java  # noqa: F401
from archgraph.extractors.deep import go as _go  # noqa: F401

logger = logging.getLogger(__name__)

# Try optional languages
try:
    from archgraph.extractors.deep import kotlin as _kotlin  # noqa: F401
except Exception:
    pass

try:
    from archgraph.extractors.deep import swift as _swift  # noqa: F401
except Exception:
    pass


class TreeSitterDeepExtractor(BaseExtractor):
    """Deep analysis (CFG, data flow, taint) for non-C/C++ languages via tree-sitter."""

    def __init__(self, languages: list[str] | None = None) -> None:
        self._requested = languages
        self._parsers: dict[str, ts.Parser] = {}
        self._specs: dict[str, LangSpec] = {}
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Initialize tree-sitter parsers for each available deep-analysis language."""
        for lang, spec in REGISTRY.items():
            if self._requested is not None and lang not in self._requested:
                continue
            try:
                mod = importlib.import_module(spec.ts_module)
                ts_lang = ts.Language(mod.language())
                parser = ts.Parser(ts_lang)
                self._parsers[lang] = parser
                self._specs[lang] = spec
                logger.debug("Deep analysis parser initialized for %s", lang)
            except (ImportError, Exception) as e:
                logger.debug("Skipping deep analysis for %s: %s", lang, e)

    @property
    def available_languages(self) -> list[str]:
        """Return list of languages that have parsers loaded."""
        return sorted(self._parsers.keys())

    def extract(self, repo_path: Path, **kwargs: object) -> GraphData:
        """Extract deep analysis data from supported source files."""
        graph = GraphData()
        repo = repo_path.resolve()

        if not self._parsers:
            logger.info("No deep analysis languages available — skipping")
            return graph

        files = self._collect_files(repo)
        if not files:
            logger.info("No files found for tree-sitter deep analysis")
            return graph

        logger.info(
            "Tree-sitter deep analysis: %d files (%s)",
            len(files),
            ", ".join(self.available_languages),
        )

        for fpath, lang in files:
            try:
                self._analyze_file(fpath, lang, repo, graph)
            except Exception:
                logger.debug("Deep analysis failed for %s", fpath, exc_info=True)

        return graph

    def _collect_files(self, repo: Path) -> list[tuple[Path, str]]:
        """Collect files matching registered language extensions."""
        # Build extension -> language mapping
        ext_map: dict[str, str] = {}
        for lang, spec in self._specs.items():
            for ext in spec.extensions:
                ext_map[ext] = lang

        files: list[tuple[Path, str]] = []
        for root, dirs, filenames in os.walk(repo):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if fname in SKIP_FILES:
                    continue
                fpath = Path(root) / fname
                suffix = fpath.suffix.lower()
                if suffix in ext_map:
                    files.append((fpath, ext_map[suffix]))
        return sorted(files, key=lambda x: x[0])

    def _analyze_file(
        self, fpath: Path, lang: str, repo: Path, graph: GraphData
    ) -> None:
        """Parse and analyze a single file."""
        source = fpath.read_bytes()
        rel_path = str(fpath.relative_to(repo)) if fpath.is_relative_to(repo) else str(fpath)
        parser = self._parsers[lang]
        spec = self._specs[lang]

        tree = parser.parse(source)
        root = tree.root_node

        # Find all function definitions and analyze each
        self._walk_for_functions(root, spec, source, rel_path, graph)

    def _walk_for_functions(
        self,
        node: object,
        spec: LangSpec,
        source: bytes,
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Walk AST to find function definitions and run deep analysis on each."""
        if node.type in spec.function_def:  # type: ignore[union-attr]
            analyze_function(node, spec, source, rel_path, graph)
            return  # Don't recurse into nested functions

        for child in node.children:  # type: ignore[union-attr]
            self._walk_for_functions(child, spec, source, rel_path, graph)
