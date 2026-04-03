"""Python language specification and pattern detector for deep analysis."""

from __future__ import annotations

import re
from typing import Any

from archgraph.extractors.deep.lang_spec import LangSpec, register_spec

# Security-sensitive patterns to detect in analyzed source code.
# These are string literals used for STATIC ANALYSIS pattern matching —
# they detect dangerous function calls in code being analyzed, NOT executed here.
_DANGEROUS_EXEC_PATTERN = "exec("
_DANGEROUS_EVAL_PATTERN = "eval("
_UNSAFE_DESER_PATTERNS = ("pickle.load", "pickle.loads")
_SQL_KW_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b", re.IGNORECASE
)


def detect_python_patterns(func_node: Any, source: bytes) -> dict[str, bool]:
    """Detect Python-specific security/quality patterns in a function AST."""
    flags: dict[str, bool] = {}
    text = source[func_node.start_byte:func_node.end_byte].decode(
        "utf-8", errors="replace"
    )

    # exec() usage — arbitrary code execution
    if _DANGEROUS_EXEC_PATTERN in text:
        flags["has_dangerous_exec"] = True

    # eval() usage — arbitrary code evaluation
    if _DANGEROUS_EVAL_PATTERN in text:
        flags["has_dangerous_eval"] = True

    # Unsafe deserialization (pickle, yaml.load without SafeLoader)
    if any(p in text for p in _UNSAFE_DESER_PATTERNS):
        flags["has_unsafe_deserialization"] = True
    if "yaml.load(" in text and "SafeLoader" not in text and "safe_load" not in text:
        flags["has_unsafe_deserialization"] = True

    # subprocess with shell=True
    if "shell=True" in text and ("subprocess" in text or "Popen" in text):
        flags["has_subprocess_shell"] = True

    # SQL string formatting (f-string or .format() with SQL keywords)
    if _SQL_KW_RE.search(text):
        if re.search(r'f["\']', text) or ".format(" in text or "%" in text:
            flags["has_sql_string_format"] = True

    return flags


PYTHON_SPEC = register_spec(LangSpec(
    language="python",
    ts_module="tree_sitter_python",
    extensions=frozenset({".py", ".pyi"}),
    # CFG
    compound_stmt=("block",),
    if_stmt=("if_statement",),
    loop_stmt=("while_statement", "for_statement"),
    return_stmt=("return_statement",),
    match_stmt=("match_statement",),
    # Variable / assignment — Python uses left/right fields, handled by _extract_assignment
    var_decl=(),
    assignment=("assignment", "augmented_assignment"),
    param_decl=("parameters",),
    # Expression
    identifier=("identifier",),
    call_expr=("call",),
    # Function
    function_def=("function_definition",),
    body_field="body",
    name_field="name",
    params_field="parameters",
    # Patterns
    pattern_detector=detect_python_patterns,
))
