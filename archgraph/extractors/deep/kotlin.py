"""Kotlin language specification and pattern detector for deep analysis."""

from __future__ import annotations

from typing import Any

from archgraph.extractors.deep.lang_spec import LangSpec, register_spec


def detect_kotlin_patterns(func_node: Any, source: bytes) -> dict[str, bool]:
    """Detect Kotlin-specific patterns in a function AST."""
    flags: dict[str, bool] = {}
    text = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")

    # Coroutine usage (suspend, launch, async, withContext, etc.)
    coroutine_markers = ("launch", "async", "withContext", "coroutineScope", "runBlocking")
    header = text.split("{")[0] if "{" in text else text
    if "suspend " in header:
        flags["has_coroutine"] = True
    else:
        for marker in coroutine_markers:
            if marker in text:
                flags["has_coroutine"] = True
                break

    # Force unwrap (!!)
    if "!!" in text:
        flags["has_force_unwrap"] = True

    # Safe call (?.)
    if "?." in text:
        flags["has_safe_call"] = True

    return flags


KOTLIN_SPEC = register_spec(LangSpec(
    language="kotlin",
    ts_module="tree_sitter_kotlin",
    extensions=frozenset({".kt", ".kts"}),
    # CFG
    compound_stmt=("function_body", "statements"),
    if_stmt=("if_expression",),
    loop_stmt=("while_statement", "for_statement"),
    return_stmt=("jump_expression",),
    match_stmt=("when_expression",),
    # Variable / assignment
    var_decl=("property_declaration",),
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
    pattern_detector=detect_kotlin_patterns,
))
