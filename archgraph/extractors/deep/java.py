"""Java language specification and pattern detector for deep analysis."""

from __future__ import annotations

from typing import Any

from archgraph.extractors.deep.lang_spec import LangSpec, register_spec


def detect_java_patterns(func_node: Any, source: bytes) -> dict[str, bool]:
    """Detect Java-specific security/safety patterns in a method AST."""
    flags: dict[str, bool] = {}
    text = source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")

    # Reflection usage
    reflection_markers = (
        "Class.forName", "getMethod", "getDeclaredMethod",
        "getField", "getDeclaredField", "newInstance", ".invoke(",
    )
    for marker in reflection_markers:
        if marker in text:
            flags["has_reflection"] = True
            break

    # Serialization
    if "Serializable" in text or "ObjectInputStream" in text or "readObject" in text:
        flags["has_serialization"] = True

    # Synchronized blocks/methods
    if "synchronized" in text:
        flags["has_synchronized"] = True

    # JNI native method
    header = text.split("{")[0] if "{" in text else text
    if "native " in header:
        flags["has_native"] = True

    return flags


JAVA_SPEC = register_spec(LangSpec(
    language="java",
    ts_module="tree_sitter_java",
    extensions=frozenset({".java"}),
    # CFG
    compound_stmt=("block",),
    if_stmt=("if_statement",),
    loop_stmt=("while_statement", "for_statement", "enhanced_for_statement"),
    return_stmt=("return_statement",),
    match_stmt=("switch_expression", "switch_statement"),
    # Variable / assignment
    var_decl=("local_variable_declaration",),
    assignment=("assignment_expression",),
    param_decl=("formal_parameter",),
    # Expression
    identifier=("identifier",),
    call_expr=("method_invocation",),
    # Function
    function_def=("method_declaration", "constructor_declaration"),
    body_field="body",
    name_field="name",
    params_field="parameters",
    # Patterns
    pattern_detector=detect_java_patterns,
))
