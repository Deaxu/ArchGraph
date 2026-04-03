"""JavaScript language specification and pattern detector for deep analysis."""

from __future__ import annotations

from typing import Any

from archgraph.extractors.deep.lang_spec import LangSpec, register_spec

# Security-sensitive function names to detect in analyzed source code
_DANGEROUS_EVAL_PATTERN = "eval("
_INNER_HTML_PATTERNS = ("innerHTML", "outerHTML")
_PROTO_PATTERNS = ("__proto__", ".prototype")


def detect_js_patterns(func_node: Any, source: bytes) -> dict[str, bool]:
    """Detect JavaScript-specific security/quality patterns in a function AST."""
    flags: dict[str, bool] = {}
    text = source[func_node.start_byte:func_node.end_byte].decode(
        "utf-8", errors="replace"
    )

    # Dangerous code execution
    if _DANGEROUS_EVAL_PATTERN in text:
        flags["has_dangerous_eval"] = True

    # innerHTML/outerHTML assignment (XSS risk)
    if any(p in text for p in _INNER_HTML_PATTERNS):
        flags["has_innerHTML"] = True

    # Dynamic import() calls
    if "import(" in text:
        flags["has_dynamic_import"] = True

    # Prototype pollution
    if any(p in text for p in _PROTO_PATTERNS):
        flags["has_prototype_pollution"] = True

    return flags


JS_SPEC = register_spec(LangSpec(
    language="javascript",
    ts_module="tree_sitter_javascript",
    extensions=frozenset({".js", ".mjs", ".cjs", ".jsx"}),
    # CFG
    compound_stmt=("statement_block",),
    if_stmt=("if_statement",),
    loop_stmt=(
        "while_statement", "for_statement", "do_statement", "for_in_statement",
    ),
    return_stmt=("return_statement",),
    match_stmt=("switch_statement",),
    # Variable / assignment
    var_decl=("variable_declaration", "lexical_declaration"),
    assignment=("assignment_expression", "augmented_assignment_expression"),
    param_decl=("formal_parameters",),
    # Expression
    identifier=("identifier",),
    call_expr=("call_expression",),
    # Function
    function_def=("function_declaration", "method_definition", "arrow_function"),
    body_field="body",
    name_field="name",
    params_field="parameters",
    # Patterns
    pattern_detector=detect_js_patterns,
))
