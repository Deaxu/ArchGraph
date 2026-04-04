"""Annotation extractor — scans source files for TODO, HACK, UNSAFE, FIXME, etc."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from archgraph.config import ANNOTATION_PATTERNS, EXTENSION_MAP, SKIP_DIRS, SKIP_FILES
from archgraph.extractors.base import BaseExtractor
from archgraph.graph.schema import GraphData, NodeLabel, EdgeType

logger = logging.getLogger(__name__)

# Compiled patterns
_COMPILED_PATTERNS: dict[str, re.Pattern] = {
    name: re.compile(pattern) for name, pattern in ANNOTATION_PATTERNS.items()
}


class AnnotationExtractor(BaseExtractor):
    """Scans source files for annotation comments (TODO, HACK, UNSAFE, FIXME, etc.)."""

    def extract(self, repo_path: Path, **kwargs: object) -> GraphData:
        graph = GraphData()

        for root, dirs, filenames in os.walk(repo_path, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if fname in SKIP_FILES:
                    continue
                fpath = Path(root) / fname
                if fpath.suffix not in EXTENSION_MAP:
                    continue
                try:
                    self._scan_file(fpath, repo_path, graph)
                except Exception:
                    logger.exception("Error scanning %s for annotations", fpath)

        return graph

    def _scan_file(self, file_path: Path, repo_path: Path, graph: GraphData) -> None:
        """Scan a single file for annotation patterns."""
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        rel_path = str(file_path.relative_to(repo_path)).replace("\\", "/")
        file_id = f"file:{rel_path}"

        for line_num, line in enumerate(text.splitlines(), start=1):
            for ann_type, pattern in _COMPILED_PATTERNS.items():
                if pattern.search(line):
                    ann_id = f"ann:{rel_path}:{line_num}:{ann_type}"
                    # Extract context: the comment text around the annotation
                    context = line.strip()[:300]

                    graph.add_node(
                        ann_id,
                        NodeLabel.ANNOTATION,
                        text=context,
                        type=ann_type,
                        file=rel_path,
                        line=line_num,
                    )
                    graph.add_edge(file_id, ann_id, EdgeType.HAS_ANNOTATION)
