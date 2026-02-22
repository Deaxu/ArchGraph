"""Swift language specification and pattern detector for deep analysis."""

from __future__ import annotations

from typing import Any

from archgraph.extractors.deep.lang_spec import LangSpec, register_spec


def detect_swift_patterns(func_node: Any, source: bytes) -> dict[str, bool]:
    """Detect Swift-specific patterns in a function AST."""
    flags: dict[str, bool] = {}
    text = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")

    # Force unwrap (!)
    # Heuristic: identifier followed by ! that isn't !=
    if _has_descendant_type(func_node, "forced_unwrap_expression"):
        flags["has_force_unwrap"] = True
    elif "!" in text:
        # Simple fallback: check for ! after identifiers (not != or !!)
        import re
        if re.search(r'[a-zA-Z_]\w*\s*!(?!=)', text):
            flags["has_force_unwrap"] = True

    # Optional chaining (?.)
    if "?." in text:
        flags["has_optional_chain"] = True

    # Force try (try!)
    if "try!" in text:
        flags["has_force_try"] = True

    # Weak references
    if "weak " in text or "unowned " in text:
        flags["has_weak_ref"] = True

    return flags


def _has_descendant_type(node: Any, target_type: str) -> bool:
    """Check if any descendant has the given node type."""
    for child in node.children:
        if child.type == target_type:
            return True
        if _has_descendant_type(child, target_type):
            return True
    return False


SWIFT_SPEC = register_spec(LangSpec(
    language="swift",
    ts_module="tree_sitter_swift",
    extensions=frozenset({".swift"}),
    # CFG
    compound_stmt=("code_block",),
    if_stmt=("if_statement",),
    loop_stmt=("while_statement", "for_in_statement", "repeat_while_statement"),
    return_stmt=("return_statement",),
    match_stmt=("switch_statement",),
    # Variable / assignment
    var_decl=("variable_declaration",),
    assignment=("assignment",),
    param_decl=("parameter",),
    # Expression
    identifier=("simple_identifier",),
    call_expr=("call_expression",),
    # Function
    function_def=("function_declaration",),
    body_field="body",
    name_field="name",
    params_field="parameters",
    # Patterns
    pattern_detector=detect_swift_patterns,
))
