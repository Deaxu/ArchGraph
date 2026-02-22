"""Language specification dataclass and registry for tree-sitter deep analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LangSpec:
    """Describes how to map tree-sitter AST node types to CFG/data-flow concepts."""

    language: str
    ts_module: str  # e.g. "tree_sitter_rust"
    extensions: frozenset[str]

    # CFG node types
    compound_stmt: tuple[str, ...]
    if_stmt: tuple[str, ...]
    loop_stmt: tuple[str, ...]
    return_stmt: tuple[str, ...]

    # Variable / assignment
    var_decl: tuple[str, ...]
    assignment: tuple[str, ...]
    param_decl: tuple[str, ...]

    # Expression
    identifier: tuple[str, ...]
    call_expr: tuple[str, ...]

    # Function detection
    function_def: tuple[str, ...]

    # Fields with defaults (must come after all non-default fields)
    match_stmt: tuple[str, ...] = ()
    body_field: str = "body"
    name_field: str = "name"
    params_field: str = "parameters"

    # Pattern detector — Callable[[ts.Node, bytes], dict[str, bool]] | None
    pattern_detector: Any = field(default=None, hash=False, compare=False)


# Global registry: language name -> LangSpec
REGISTRY: dict[str, LangSpec] = {}


def register_spec(spec: LangSpec) -> LangSpec:
    """Register a LangSpec into the global REGISTRY."""
    REGISTRY[spec.language] = spec
    return spec
