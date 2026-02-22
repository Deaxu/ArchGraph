"""Go language specification and pattern detector for deep analysis."""

from __future__ import annotations

from typing import Any

from archgraph.extractors.deep.lang_spec import LangSpec, register_spec


def detect_go_patterns(func_node: Any, source: bytes) -> dict[str, bool]:
    """Detect Go-specific patterns in a function AST."""
    flags: dict[str, bool] = {}
    text = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")

    # Goroutine spawn
    if _has_descendant_type(func_node, "go_statement"):
        flags["has_goroutine"] = True

    # Defer
    if _has_descendant_type(func_node, "defer_statement"):
        flags["has_defer"] = True

    # Channel operations (<- operator)
    if "<-" in text:
        flags["has_channel_op"] = True

    # unsafe.Pointer
    if "unsafe.Pointer" in text:
        flags["has_unsafe_pointer"] = True

    # Error check pattern (if err != nil)
    if "err != nil" in text or "err == nil" in text:
        flags["has_error_check"] = True

    return flags


def _has_descendant_type(node: Any, target_type: str) -> bool:
    """Check if any descendant has the given node type."""
    for child in node.children:
        if child.type == target_type:
            return True
        if _has_descendant_type(child, target_type):
            return True
    return False


GO_SPEC = register_spec(LangSpec(
    language="go",
    ts_module="tree_sitter_go",
    extensions=frozenset({".go"}),
    # CFG
    compound_stmt=("block", "statement_list"),
    if_stmt=("if_statement",),
    loop_stmt=("for_statement",),
    return_stmt=("return_statement",),
    # Variable / assignment
    var_decl=("var_declaration", "short_var_declaration"),
    assignment=("assignment_statement",),
    param_decl=("parameter_declaration",),
    # Expression
    identifier=("identifier",),
    call_expr=("call_expression",),
    # Function
    function_def=("function_declaration", "method_declaration"),
    body_field="body",
    name_field="name",
    params_field="parameters",
    # Patterns
    pattern_detector=detect_go_patterns,
))
