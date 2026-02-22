"""Rust language specification and pattern detector for deep analysis."""

from __future__ import annotations

from typing import Any

from archgraph.extractors.deep.lang_spec import LangSpec, register_spec


def detect_rust_patterns(func_node: Any, source: bytes) -> dict[str, bool]:
    """Detect Rust-specific security/safety patterns in a function AST."""
    flags: dict[str, bool] = {}
    text = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")

    # unsafe block inside the function
    if _has_descendant_type(func_node, "unsafe_block"):
        flags["has_unsafe_block"] = True

    # The function itself is declared unsafe
    for child in func_node.children:
        if child.type == "function_modifiers" or child.type == "visibility_modifier":
            mod_text = source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
            if "unsafe" in mod_text:
                flags["is_unsafe_fn"] = True

    # Check first-level tokens for unsafe keyword before fn
    if "unsafe " in text.split("{")[0] if "{" in text else "unsafe " in text:
        flags["is_unsafe_fn"] = True

    # transmute usage
    if "transmute" in text:
        flags["has_transmute"] = True

    # .unwrap() usage
    if ".unwrap()" in text:
        flags["has_unwrap"] = True

    # Raw pointer dereference (*ptr)
    if _has_descendant_type(func_node, "dereference_expression"):
        # Check if it involves a raw pointer — heuristic: any deref in unsafe block
        flags["has_raw_deref"] = True

    return flags


def _has_descendant_type(node: Any, target_type: str) -> bool:
    """Check if any descendant has the given node type."""
    for child in node.children:
        if child.type == target_type:
            return True
        if _has_descendant_type(child, target_type):
            return True
    return False


RUST_SPEC = register_spec(LangSpec(
    language="rust",
    ts_module="tree_sitter_rust",
    extensions=frozenset({".rs"}),
    # CFG
    compound_stmt=("block",),
    if_stmt=("if_expression",),
    loop_stmt=("while_expression", "for_expression", "loop_expression"),
    return_stmt=("return_expression",),
    match_stmt=("match_expression",),
    # Variable / assignment
    var_decl=("let_declaration",),
    assignment=("assignment_expression", "compound_assignment_expr"),
    param_decl=("parameter",),
    # Expression
    identifier=("identifier",),
    call_expr=("call_expression",),
    # Function
    function_def=("function_item",),
    body_field="body",
    name_field="name",
    params_field="parameters",
    # Patterns
    pattern_detector=detect_rust_patterns,
))
