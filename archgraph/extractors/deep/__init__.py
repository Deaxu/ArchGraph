"""Tree-sitter deep analysis extractor for Rust, Java, Kotlin, Go, Swift,
JavaScript, TypeScript, and Python.

Provides intra-procedural CFG, data flow, and taint analysis using tree-sitter
AST, extending the same capabilities that ClangExtractor provides for C/C++.
"""

from __future__ import annotations

import importlib
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import tree_sitter as ts

from archgraph.config import SKIP_DIRS, SKIP_FILES
from archgraph.extractors.base import BaseExtractor
from archgraph.extractors.deep.engine import analyze_function
from archgraph.extractors.deep.lang_spec import REGISTRY, LangSpec
from archgraph.graph.schema import GraphData

# Import language specs to trigger registration.
# Core languages — tree-sitter grammars are required dependencies.
from archgraph.extractors.deep import rust as _rust  # noqa: F401
from archgraph.extractors.deep import java as _java  # noqa: F401
from archgraph.extractors.deep import go as _go  # noqa: F401
from archgraph.extractors.deep import javascript as _javascript  # noqa: F401
from archgraph.extractors.deep import typescript as _typescript  # noqa: F401
from archgraph.extractors.deep import python_spec as _python_spec  # noqa: F401

logger = logging.getLogger(__name__)

# Optional languages — grammars installed via extras (pip install archgraph[kotlin] etc.)
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
        self._ts_languages: dict[str, ts.Language] = {}
        self._specs: dict[str, LangSpec] = {}
        self._thread_local = threading.local()
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Initialize tree-sitter parsers for each available deep-analysis language."""
        for lang, spec in REGISTRY.items():
            if self._requested is not None and lang not in self._requested:
                continue
            try:
                mod = importlib.import_module(spec.ts_module)
                # tree-sitter 0.24+ API: language() returns a Language capsule.
                # TypeScript module exposes language_typescript() instead.
                if hasattr(mod, "language"):
                    lang_func = mod.language
                elif hasattr(mod, f"language_{lang}"):
                    lang_func = getattr(mod, f"language_{lang}")
                else:
                    raise AttributeError(
                        f"No language function found in {spec.ts_module}"
                    )
                ts_lang = ts.Language(lang_func())
                parser = ts.Parser(ts_lang)
                self._parsers[lang] = parser
                self._ts_languages[lang] = ts_lang
                self._specs[lang] = spec
                logger.debug("Deep analysis parser initialized for %s", lang)
            except (ImportError, Exception) as e:
                logger.debug("Skipping deep analysis for %s: %s", lang, e)

    def _get_thread_parser(self, lang: str) -> ts.Parser:
        """Get a thread-local parser for the given language."""
        parsers = getattr(self._thread_local, "parsers", None)
        if parsers is None:
            parsers = {}
            self._thread_local.parsers = parsers
        if lang not in parsers:
            ts_lang = self._ts_languages[lang]
            parsers[lang] = ts.Parser(ts_lang)
        return parsers[lang]

    @property
    def available_languages(self) -> list[str]:
        """Return list of languages that have parsers loaded."""
        return sorted(self._parsers.keys())

    def extract(self, repo_path: Path, **kwargs: object) -> GraphData:
        """Extract deep analysis data from supported source files."""
        workers = kwargs.get("workers", 1)
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

        if workers and workers > 1 and len(files) > 1:
            return self._extract_parallel(files, repo, workers)

        for fpath, lang in files:
            try:
                self._analyze_file(fpath, lang, repo, graph)
            except Exception:
                logger.debug("Deep analysis failed for %s", fpath, exc_info=True)

        return graph

    def _extract_parallel(
        self, files: list[tuple[Path, str]], repo: Path, workers: int
    ) -> GraphData:
        """Analyze files in parallel using ThreadPoolExecutor."""
        graph = GraphData()

        def _process(args: tuple[Path, str]) -> GraphData:
            fpath, lang = args
            return self._analyze_file_to_graph(fpath, lang, repo)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for sub_graph in pool.map(_process, files):
                graph.merge(sub_graph)

        return graph

    def _analyze_file_to_graph(
        self, fpath: Path, lang: str, repo: Path
    ) -> GraphData:
        """Analyze a single file and return its own GraphData (thread-safe)."""
        graph = GraphData()
        try:
            source = fpath.read_bytes()
            rel_path = (
                str(fpath.relative_to(repo)) if fpath.is_relative_to(repo) else str(fpath)
            ).replace("\\", "/")
            parser = self._get_thread_parser(lang)
            spec = self._specs[lang]
            tree = parser.parse(source)
            root = tree.root_node
            self._walk_for_functions(root, spec, source, rel_path, graph)
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
        rel_path = (
            str(fpath.relative_to(repo)) if fpath.is_relative_to(repo) else str(fpath)
        ).replace("\\", "/")
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
