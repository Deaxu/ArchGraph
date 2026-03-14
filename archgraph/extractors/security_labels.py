"""Security labeler — adds security-related labels to function nodes."""

from __future__ import annotations

import logging
import re

from archgraph.config import (
    ALLOCATORS,
    CRYPTO_FUNCTIONS,
    DANGEROUS_SINKS,
    INPUT_SOURCES,
    PARSER_FUNCTIONS,
)
from archgraph.graph.schema import GraphData, NodeLabel

logger = logging.getLogger(__name__)


class SecurityLabeler:
    """Post-processor that labels Function nodes with security-relevant attributes."""

    def label(self, graph: GraphData) -> int:
        """Apply security labels to all Function nodes. Returns count of labeled nodes."""
        labeled = 0

        for node in graph.nodes:
            if node.label != NodeLabel.FUNCTION:
                continue

            name = node.properties.get("name", "")
            if not name:
                continue

            changed = False

            if self._matches(name, INPUT_SOURCES):
                node.properties["is_input_source"] = True
                changed = True

            if self._matches(name, DANGEROUS_SINKS):
                node.properties["is_dangerous_sink"] = True
                changed = True

            if self._matches(name, ALLOCATORS):
                node.properties["is_allocator"] = True
                changed = True

            if self._matches(name, CRYPTO_FUNCTIONS):
                node.properties["is_crypto"] = True
                changed = True

            if self._matches(name, PARSER_FUNCTIONS):
                node.properties["is_parser"] = True
                changed = True

            # Check for unsafe patterns in function body / name
            if self._has_unsafe_pattern(node):
                node.properties["touches_unsafe"] = True
                changed = True

            if changed:
                labeled += 1

            # Calculate risk score (0-100)
            risk = 0
            if node.properties.get("is_input_source"):
                risk += 30
            if node.properties.get("is_dangerous_sink"):
                risk += 30
            if node.properties.get("touches_unsafe"):
                risk += 20
            if node.properties.get("is_allocator"):
                risk += 10
            if node.properties.get("is_parser"):
                risk += 10
            node.properties["risk_score"] = min(risk, 100)

        logger.info("Applied security labels to %d functions", labeled)
        return labeled

    def _matches(self, name: str, patterns: frozenset[str]) -> bool:
        """Check if the function name matches any of the patterns."""
        # Exact match
        if name in patterns:
            return True
        # Check if the last segment matches (for qualified names like Foo::bar)
        base = name.rsplit("::", 1)[-1].rsplit(".", 1)[-1].rsplit("->", 1)[-1]
        if base in patterns:
            return True
        # Partial match for compound names (e.g., "readLine" contains "read")
        name_lower = name.lower()
        for pattern in patterns:
            if pattern.lower() in name_lower:
                return True
        return False

    def _has_unsafe_pattern(self, node) -> bool:
        """Check if the function touches unsafe constructs."""
        name = node.properties.get("name", "").lower()
        # Rust unsafe
        if "unsafe" in name:
            return True
        # C void* casts, raw pointers
        params = node.properties.get("params", "")
        if "void*" in params or "void *" in params:
            return True
        return False
