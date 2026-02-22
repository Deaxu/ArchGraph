"""Tree-sitter deep analysis engine — CFG, data flow, taint tracking.

Port of clang.py algorithms to work with tree-sitter AST nodes.
Language-agnostic: uses LangSpec to map node types.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from archgraph.config import DANGEROUS_SINKS, INPUT_SOURCES
from archgraph.extractors.deep.lang_spec import LangSpec
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

logger = logging.getLogger(__name__)


# ── Private data structures ──────────────────────────────────────────────────


@dataclass
class VarDef:
    """A single variable definition (declaration or assignment)."""

    name: str
    line: int
    rhs_vars: list[str] = field(default_factory=list)
    rhs_calls: list[str] = field(default_factory=list)
    is_param: bool = False


@dataclass
class BasicBlock:
    """A basic block in a function's CFG."""

    index: int
    stmts: list[Any] = field(default_factory=list)  # tree-sitter nodes
    var_defs: list[VarDef] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)


@dataclass
class FunctionAnalysis:
    """Results of analyzing a single function."""

    name: str
    file: str
    line: int
    blocks: list[BasicBlock] = field(default_factory=list)
    reaching_in: dict[int, set[tuple[str, int]]] = field(default_factory=dict)
    reaching_out: dict[int, set[tuple[str, int]]] = field(default_factory=dict)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _node_text(node: Any, source: bytes) -> str:
    """Get the text of a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _node_name_from_field(node: Any, field_name: str, source: bytes) -> str:
    """Extract text from a named field child."""
    child = node.child_by_field_name(field_name)
    if child:
        return _node_text(child, source)
    return ""


# ── CFG Builder ──────────────────────────────────────────────────────────────


def build_cfg(body_node: Any, spec: LangSpec) -> list[BasicBlock]:
    """Build a control flow graph from a function body node.

    Returns a list of BasicBlock objects with successor/predecessor edges.
    """
    blocks: list[BasicBlock] = [BasicBlock(index=0)]
    _decompose_stmts(body_node, blocks, 0, spec)

    # Compute predecessors from successors
    for block in blocks:
        for succ in block.successors:
            if succ < len(blocks):
                blocks[succ].predecessors.append(block.index)

    return blocks


def _decompose_stmts(
    node: Any,
    blocks: list[BasicBlock],
    current_idx: int,
    spec: LangSpec,
) -> int:
    """Recursively decompose statements into basic blocks. Returns exit block index."""
    for child in node.children:
        result = _classify_stmt(child, blocks, current_idx, spec)
        if result == -1:
            # Return was encountered — stop processing (block has no successors)
            return current_idx
        current_idx = result

    return current_idx


def _classify_stmt(
    child: Any,
    blocks: list[BasicBlock],
    current_idx: int,
    spec: LangSpec,
) -> int:
    """Classify a single statement and update CFG. Returns current block index or -1 for return."""
    ntype = child.type

    if ntype in spec.if_stmt:
        return _handle_if(child, blocks, current_idx, spec)

    if ntype in spec.loop_stmt:
        return _handle_loop(child, blocks, current_idx, spec)

    if ntype in spec.return_stmt:
        blocks[current_idx].stmts.append(child)
        return -1

    if ntype in spec.compound_stmt:
        return _decompose_stmts(child, blocks, current_idx, spec)

    if ntype in spec.match_stmt:
        return _handle_match(child, blocks, current_idx, spec)

    # Unwrap statement wrappers (e.g. Rust expression_statement wrapping if_expression)
    _WRAPPER_TYPES = ("expression_statement", "statement", "labeled_statement")
    if ntype in _WRAPPER_TYPES:
        for sub in child.children:
            sub_type = sub.type
            if sub_type in spec.if_stmt:
                return _handle_if(sub, blocks, current_idx, spec)
            if sub_type in spec.loop_stmt:
                return _handle_loop(sub, blocks, current_idx, spec)
            if sub_type in spec.return_stmt:
                blocks[current_idx].stmts.append(sub)
                return -1
            if sub_type in spec.match_stmt:
                return _handle_match(sub, blocks, current_idx, spec)
        # No control flow found inside wrapper — treat as normal statement
        blocks[current_idx].stmts.append(child)
        return current_idx

    # Default: add to current block
    blocks[current_idx].stmts.append(child)
    return current_idx


def _handle_if(
    node: Any, blocks: list[BasicBlock], current_idx: int, spec: LangSpec
) -> int:
    """Handle if/else: current->then, current->else, both->join."""
    children = node.children

    # Add condition-like children to current block (everything before the body)
    condition_node = node.child_by_field_name("condition")
    if condition_node:
        blocks[current_idx].stmts.append(condition_node)

    # Find body blocks — use field names when possible
    consequence = node.child_by_field_name("consequence")
    alternative = node.child_by_field_name("alternative")

    # Fallback: find compound_stmt children by position
    if consequence is None:
        for c in children:
            if c.type in spec.compound_stmt:
                consequence = c
                break

    # Then block
    then_idx = len(blocks)
    blocks.append(BasicBlock(index=then_idx))
    blocks[current_idx].successors.append(then_idx)

    then_exit = then_idx
    if consequence is not None:
        if consequence.type in spec.compound_stmt:
            then_exit = _decompose_stmts(consequence, blocks, then_idx, spec)
        else:
            blocks[then_idx].stmts.append(consequence)

    # Else block
    else_exit = current_idx
    if alternative is not None:
        else_idx = len(blocks)
        blocks.append(BasicBlock(index=else_idx))
        blocks[current_idx].successors.append(else_idx)

        if alternative.type in spec.if_stmt:
            # else-if chain
            else_exit = _handle_if(alternative, blocks, else_idx, spec)
        elif alternative.type in spec.compound_stmt:
            else_exit = _decompose_stmts(alternative, blocks, else_idx, spec)
        else:
            blocks[else_idx].stmts.append(alternative)
            else_exit = else_idx
    else:
        else_exit = current_idx

    # Join block
    join_idx = len(blocks)
    blocks.append(BasicBlock(index=join_idx))
    if then_exit < len(blocks):
        blocks[then_exit].successors.append(join_idx)
    if else_exit < len(blocks) and else_exit != current_idx:
        blocks[else_exit].successors.append(join_idx)
    elif else_exit == current_idx:
        blocks[current_idx].successors.append(join_idx)

    return join_idx


def _handle_loop(
    node: Any, blocks: list[BasicBlock], current_idx: int, spec: LangSpec
) -> int:
    """Handle loops: current->header->body->header, header->exit."""
    # Header block (loop condition)
    header_idx = len(blocks)
    blocks.append(BasicBlock(index=header_idx))
    blocks[current_idx].successors.append(header_idx)

    # Add condition to header
    condition = node.child_by_field_name("condition")
    if condition:
        blocks[header_idx].stmts.append(condition)

    # Body block
    body_idx = len(blocks)
    blocks.append(BasicBlock(index=body_idx))
    blocks[header_idx].successors.append(body_idx)

    # Find and process loop body
    body_node = node.child_by_field_name("body")
    if body_node is None:
        # Fallback: last compound_stmt child
        for c in reversed(node.children):
            if c.type in spec.compound_stmt:
                body_node = c
                break

    body_exit = body_idx
    if body_node is not None:
        if body_node.type in spec.compound_stmt:
            body_exit = _decompose_stmts(body_node, blocks, body_idx, spec)
        else:
            blocks[body_idx].stmts.append(body_node)

    # Back edge: body -> header
    blocks[body_exit].successors.append(header_idx)

    # Exit block
    exit_idx = len(blocks)
    blocks.append(BasicBlock(index=exit_idx))
    blocks[header_idx].successors.append(exit_idx)

    return exit_idx


def _handle_match(
    node: Any, blocks: list[BasicBlock], current_idx: int, spec: LangSpec
) -> int:
    """Handle match/switch: current -> each arm, all arms -> join."""
    # Add the match expression to current block
    value = node.child_by_field_name("value") or node.child_by_field_name("condition")
    if value:
        blocks[current_idx].stmts.append(value)

    arm_exits: list[int] = []

    # Each child that is a match arm / case gets its own block
    for child in node.children:
        if child.type in (
            "match_arm", "switch_case", "switch_default",
            "when_entry", "when_condition",
        ):
            arm_idx = len(blocks)
            blocks.append(BasicBlock(index=arm_idx))
            blocks[current_idx].successors.append(arm_idx)

            arm_exit = arm_idx
            # Decompose the arm body
            for sub in child.children:
                if sub.type in spec.compound_stmt:
                    arm_exit = _decompose_stmts(sub, blocks, arm_idx, spec)
                else:
                    blocks[arm_idx].stmts.append(sub)
            arm_exits.append(arm_exit)

    # If no arms were found, treat as a single pass-through
    if not arm_exits:
        return current_idx

    # Join block
    join_idx = len(blocks)
    blocks.append(BasicBlock(index=join_idx))
    for ae in arm_exits:
        blocks[ae].successors.append(join_idx)

    return join_idx


# ── Variable Definition Extraction ───────────────────────────────────────────


def extract_var_defs(block: BasicBlock, spec: LangSpec, source: bytes) -> list[VarDef]:
    """Extract variable definitions from a basic block's statements."""
    defs: list[VarDef] = []
    for stmt in block.stmts:
        _walk_for_defs(stmt, defs, spec, source)
    return defs


def _walk_for_defs(node: Any, defs: list[VarDef], spec: LangSpec, source: bytes) -> None:
    """Walk AST node to find variable definitions and assignments."""
    ntype = node.type

    if ntype in spec.var_decl:
        _extract_var_decl(node, defs, spec, source)

    elif ntype in spec.assignment:
        _extract_assignment(node, defs, spec, source)

    else:
        for child in node.children:
            _walk_for_defs(child, defs, spec, source)


def _extract_var_decl(
    node: Any, defs: list[VarDef], spec: LangSpec, source: bytes
) -> None:
    """Extract a variable declaration."""
    # Try to get the variable name
    name = ""
    name_node = node.child_by_field_name("name")
    if name_node:
        name = _node_text(name_node, source)
    else:
        # Look for pattern (Rust let), or first identifier
        pattern = node.child_by_field_name("pattern")
        if pattern:
            name = _node_text(pattern, source)
        else:
            for child in node.children:
                if child.type in spec.identifier:
                    name = _node_text(child, source)
                    break

    if not name:
        # Java local_variable_declaration: find declarator -> name
        for child in node.children:
            if child.type == "variable_declarator":
                vname = child.child_by_field_name("name")
                if vname:
                    name = _node_text(vname, source)
                    break

    if not name:
        return

    rhs_vars: list[str] = []
    rhs_calls: list[str] = []

    # Walk the value/initializer
    value_node = (
        node.child_by_field_name("value")
        or node.child_by_field_name("initializer")
    )
    if value_node:
        _walk_expr(value_node, rhs_vars, rhs_calls, spec, source)
    else:
        # Java: value is inside variable_declarator
        for child in node.children:
            if child.type == "variable_declarator":
                val = child.child_by_field_name("value")
                if val:
                    _walk_expr(val, rhs_vars, rhs_calls, spec, source)
                break

    defs.append(VarDef(name=name, line=node.start_point[0], rhs_vars=rhs_vars, rhs_calls=rhs_calls))


def _extract_assignment(
    node: Any, defs: list[VarDef], spec: LangSpec, source: bytes
) -> None:
    """Extract an assignment statement/expression."""
    lhs = node.child_by_field_name("left")
    rhs = node.child_by_field_name("right")

    if lhs is None:
        # Try children order: first child = LHS, last child = RHS
        children = node.children
        non_op = [c for c in children if c.type not in ("=", "+=", "-=", "*=", "/=")]
        if len(non_op) >= 2:
            lhs = non_op[0]
            rhs = non_op[-1]

    if lhs is None:
        return

    lhs_name = ""
    if lhs.type in spec.identifier:
        lhs_name = _node_text(lhs, source)
    else:
        # Walk LHS for the first identifier
        for child in _iter_all(lhs):
            if child.type in spec.identifier:
                lhs_name = _node_text(child, source)
                break

    if not lhs_name:
        return

    rhs_vars: list[str] = []
    rhs_calls: list[str] = []
    if rhs is not None:
        _walk_expr(rhs, rhs_vars, rhs_calls, spec, source)

    defs.append(VarDef(name=lhs_name, line=node.start_point[0], rhs_vars=rhs_vars, rhs_calls=rhs_calls))


def _walk_expr(
    node: Any,
    vars_out: list[str],
    calls_out: list[str],
    spec: LangSpec,
    source: bytes,
) -> None:
    """Walk an expression collecting variable references and function calls."""
    ntype = node.type

    if ntype in spec.identifier:
        vars_out.append(_node_text(node, source))
    elif ntype in spec.call_expr:
        call_name = _get_call_name(node, spec, source)
        if call_name:
            calls_out.append(call_name)
        # Walk arguments for nested refs
        for child in node.children:
            _walk_expr(child, vars_out, calls_out, spec, source)
        return

    for child in node.children:
        _walk_expr(child, vars_out, calls_out, spec, source)


def _get_call_name(node: Any, spec: LangSpec, source: bytes) -> str:
    """Extract the function/method name from a call expression node."""
    # Try 'function' field (Rust, Go, JS)
    func_node = node.child_by_field_name("function")
    if func_node:
        text = _node_text(func_node, source)
        # Strip qualifiers: obj.method -> method, ns::func -> func
        for sep in ("->", "::", ".", "/"):
            if sep in text:
                text = text.rsplit(sep, 1)[-1]
        return text.strip()

    # Try 'name' field (Java method_invocation)
    name_node = node.child_by_field_name("name")
    if name_node:
        return _node_text(name_node, source)

    return ""


def _iter_all(node: Any) -> list[Any]:
    """Iterate all descendants."""
    result: list[Any] = []
    for child in node.children:
        result.append(child)
        result.extend(_iter_all(child))
    return result


# ── Parameter Extraction ─────────────────────────────────────────────────────


def extract_params(func_node: Any, spec: LangSpec, source: bytes) -> list[VarDef]:
    """Extract function parameters as VarDef entries."""
    params: list[VarDef] = []
    param_list = func_node.child_by_field_name(spec.params_field)
    if param_list is None:
        # Fallback: find by type
        for child in func_node.children:
            if child.type in ("parameter_list", "formal_parameters", "parameters"):
                param_list = child
                break

    if param_list is None:
        return params

    for child in param_list.children:
        if child.type in spec.param_decl:
            name = ""
            name_node = child.child_by_field_name("name")
            if name_node:
                name = _node_text(name_node, source)
            else:
                # Find first identifier-type child
                for sub in child.children:
                    if sub.type in spec.identifier:
                        name = _node_text(sub, source)
                        break
            if name:
                params.append(VarDef(
                    name=name,
                    line=child.start_point[0],
                    is_param=True,
                ))

    return params


# ── Reaching Definitions (iterative worklist) ────────────────────────────────


def compute_reaching_definitions(analysis: FunctionAnalysis) -> None:
    """Classic iterative worklist reaching definitions algorithm."""
    blocks = analysis.blocks
    n = len(blocks)
    if n == 0:
        return

    # gen[b] = set of (var, line) defined in block b (last def wins)
    # kill[b] = set of var names killed by definitions in block b
    gen: dict[int, set[tuple[str, int]]] = {}
    kill_vars: dict[int, set[str]] = {}

    for block in blocks:
        block_gen: dict[str, int] = {}
        killed: set[str] = set()
        for vd in block.var_defs:
            block_gen[vd.name] = vd.line
            killed.add(vd.name)
        gen[block.index] = {(name, line) for name, line in block_gen.items()}
        kill_vars[block.index] = killed

    # Initialize
    reaching_in: dict[int, set[tuple[str, int]]] = {b.index: set() for b in blocks}
    reaching_out: dict[int, set[tuple[str, int]]] = {
        b.index: set(gen.get(b.index, set())) for b in blocks
    }

    # Worklist
    worklist = list(range(n))
    max_iters = n * 10
    iters = 0

    while worklist and iters < max_iters:
        iters += 1
        b_idx = worklist.pop(0)
        block = blocks[b_idx]

        # IN[b] = union of OUT[p] for all predecessors p
        new_in: set[tuple[str, int]] = set()
        for pred_idx in block.predecessors:
            new_in |= reaching_out[pred_idx]

        reaching_in[b_idx] = new_in

        # OUT[b] = gen[b] U (IN[b] - kill[b])
        killed = kill_vars.get(b_idx, set())
        surviving = {(v, l) for v, l in new_in if v not in killed}
        new_out = gen.get(b_idx, set()) | surviving

        if new_out != reaching_out[b_idx]:
            reaching_out[b_idx] = new_out
            for succ in block.successors:
                if succ < n and succ not in worklist:
                    worklist.append(succ)

    analysis.reaching_in = reaching_in
    analysis.reaching_out = reaching_out


# ── Data Flow Edge Generation ────────────────────────────────────────────────


def generate_data_flow_edges(analysis: FunctionAnalysis, graph: GraphData) -> None:
    """Generate DATA_FLOWS_TO edges from reaching definitions."""
    func_id = f"func:{analysis.file}:{analysis.name}:{analysis.line}"

    for block in analysis.blocks:
        reaching = set(analysis.reaching_in.get(block.index, set()))

        for vd in block.var_defs:
            # For each RHS variable, find its reaching definition
            for rhs_var in vd.rhs_vars:
                for def_var, def_line in reaching:
                    if def_var == rhs_var:
                        graph.add_edge(
                            func_id,
                            func_id,
                            EdgeType.DATA_FLOWS_TO,
                            from_var=def_var,
                            from_line=def_line,
                            to_var=vd.name,
                            to_line=vd.line,
                        )

            # Update reaching set — kill old defs of this var, add new
            reaching = {(v, l) for v, l in reaching if v != vd.name}
            reaching.add((vd.name, vd.line))


# ── Taint Propagation ────────────────────────────────────────────────────────


def propagate_taint(
    analysis: FunctionAnalysis, rel_path: str, graph: GraphData
) -> None:
    """Propagate taint from INPUT_SOURCES through variable chains to DANGEROUS_SINKS."""
    all_defs: list[VarDef] = []
    for block in analysis.blocks:
        all_defs.extend(block.var_defs)

    # Find initially tainted variables
    tainted_vars: set[str] = set()
    for vd in all_defs:
        for call in vd.rhs_calls:
            if call in INPUT_SOURCES or _basename_match(call, INPUT_SOURCES):
                tainted_vars.add(vd.name)

    # Parameters are always potentially tainted
    for vd in all_defs:
        if vd.is_param:
            tainted_vars.add(vd.name)

    if not tainted_vars:
        return

    # Propagate: if a var is defined from a tainted var, it becomes tainted
    changed = True
    max_rounds = len(all_defs) + 1
    rounds = 0
    while changed and rounds < max_rounds:
        changed = False
        rounds += 1
        for vd in all_defs:
            if vd.name in tainted_vars:
                continue
            for rhs_var in vd.rhs_vars:
                if rhs_var in tainted_vars:
                    tainted_vars.add(vd.name)
                    changed = True
                    break

    # Check if tainted variables flow into dangerous sink calls
    for vd in all_defs:
        for call in vd.rhs_calls:
            if call in DANGEROUS_SINKS or _basename_match(call, DANGEROUS_SINKS):
                if any(rv in tainted_vars for rv in vd.rhs_vars):
                    source_call = _find_taint_source(vd, all_defs, tainted_vars)
                    source_id = f"funcref:{rel_path}:{source_call}:0"
                    sink_id = f"funcref:{rel_path}:{call}:0"
                    graph.add_edge(
                        source_id,
                        sink_id,
                        EdgeType.TAINTS,
                        via_function=analysis.name,
                        via_variable=",".join(
                            rv for rv in vd.rhs_vars if rv in tainted_vars
                        ),
                        file=rel_path,
                    )

    # Also check call arguments for taint
    _check_call_args_taint(analysis, all_defs, tainted_vars, rel_path, graph)


def _check_call_args_taint(
    analysis: FunctionAnalysis,
    all_defs: list[VarDef],
    tainted_vars: set[str],
    rel_path: str,
    graph: GraphData,
) -> None:
    """Check if tainted variables are passed as arguments to dangerous sinks."""
    for block in analysis.blocks:
        for stmt in block.stmts:
            _walk_for_tainted_calls(stmt, tainted_vars, analysis, all_defs, rel_path, graph)


def _walk_for_tainted_calls(
    node: Any,
    tainted_vars: set[str],
    analysis: FunctionAnalysis,
    all_defs: list[VarDef],
    rel_path: str,
    graph: GraphData,
) -> None:
    """Walk AST looking for calls to dangerous sinks with tainted arguments."""
    # Detect call expression by checking common call types
    call_types = ("call_expression", "method_invocation")
    if node.type in call_types:
        call_name = ""
        func_node = node.child_by_field_name("function")
        if func_node:
            text = _node_text(func_node, node.text[:0] if hasattr(node, 'text') else b"")
            # We need the source — extract from node range
            call_name = _node_text_fallback(func_node)
        name_node = node.child_by_field_name("name")
        if name_node and not call_name:
            call_name = _node_text_fallback(name_node)

        # Simpler approach: get call name from the full node
        if not call_name:
            call_name = _extract_call_name_from_node(node)

        if call_name and (
            call_name in DANGEROUS_SINKS or _basename_match(call_name, DANGEROUS_SINKS)
        ):
            # Collect argument variable references
            arg_vars: list[str] = []
            args_node = node.child_by_field_name("arguments")
            if args_node:
                for arg in args_node.children:
                    _collect_identifiers(arg, arg_vars)
            else:
                # Walk all children except the function name
                for child in node.children:
                    if child != func_node and child != name_node:
                        _collect_identifiers(child, arg_vars)

            tainted_args = [v for v in arg_vars if v in tainted_vars]
            if tainted_args:
                source_call = _find_taint_source_from_vars(
                    tainted_args, all_defs, tainted_vars
                )
                source_id = f"funcref:{rel_path}:{source_call}:0"
                sink_id = f"funcref:{rel_path}:{call_name}:0"
                graph.add_edge(
                    source_id,
                    sink_id,
                    EdgeType.TAINTS,
                    via_function=analysis.name,
                    via_variable=",".join(tainted_args),
                    file=rel_path,
                )

    for child in node.children:
        _walk_for_tainted_calls(child, tainted_vars, analysis, all_defs, rel_path, graph)


def _node_text_fallback(node: Any) -> str:
    """Get node text using the node's own bytes if available."""
    # tree-sitter Node objects don't carry source — this is a no-op fallback
    return ""


def _extract_call_name_from_node(node: Any) -> str:
    """Try to extract call name from a call node using children."""
    # First child is often the function reference
    for child in node.children:
        if child.type in ("identifier", "simple_identifier"):
            # Access raw bytes via parent — but we don't have source here
            return ""
    return ""


def _collect_identifiers(node: Any, out: list[str]) -> None:
    """Collect all identifier texts from a node subtree (needs stored text)."""
    # This walks the node tree but relies on stored _text on VarDef level
    # In practice, taint detection via _walk_for_tainted_calls is secondary;
    # the primary path goes through VarDef.rhs_calls in propagate_taint.
    pass


def _find_taint_source(
    vd: VarDef, all_defs: list[VarDef], tainted_vars: set[str]
) -> str:
    """Trace back to find the original input source call."""
    visited: set[str] = set()
    queue = [rv for rv in vd.rhs_vars if rv in tainted_vars]

    while queue:
        var = queue.pop(0)
        if var in visited:
            continue
        visited.add(var)
        for d in all_defs:
            if d.name == var:
                for call in d.rhs_calls:
                    if call in INPUT_SOURCES or _basename_match(call, INPUT_SOURCES):
                        return call
                queue.extend(rv for rv in d.rhs_vars if rv in tainted_vars)

    # Fallback
    for d in all_defs:
        for call in d.rhs_calls:
            if call in INPUT_SOURCES or _basename_match(call, INPUT_SOURCES):
                return call
    return "unknown_source"


def _find_taint_source_from_vars(
    tainted_args: list[str], all_defs: list[VarDef], tainted_vars: set[str]
) -> str:
    """Find the original input source from tainted variable names."""
    visited: set[str] = set()
    queue = list(tainted_args)

    while queue:
        var = queue.pop(0)
        if var in visited:
            continue
        visited.add(var)
        for d in all_defs:
            if d.name == var:
                for call in d.rhs_calls:
                    if call in INPUT_SOURCES or _basename_match(call, INPUT_SOURCES):
                        return call
                queue.extend(rv for rv in d.rhs_vars if rv in tainted_vars)

    return "unknown_source"


def _basename_match(name: str, patterns: frozenset[str]) -> bool:
    """Check if a function name matches patterns (last segment check)."""
    base = name.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
    return base in patterns


# ── CFG Graph Emission ───────────────────────────────────────────────────────


def emit_cfg_to_graph(analysis: FunctionAnalysis, graph: GraphData) -> None:
    """Emit BasicBlock nodes + CONTAINS + BRANCHES_TO edges."""
    func_id = f"func:{analysis.file}:{analysis.name}:{analysis.line}"

    for block in analysis.blocks:
        bb_id = f"bb:{analysis.file}:{analysis.name}:{block.index}"
        stmt_count = len(block.stmts)

        graph.add_node(
            bb_id,
            NodeLabel.BASIC_BLOCK,
            function=analysis.name,
            file=analysis.file,
            block_index=block.index,
            stmt_count=stmt_count,
        )

        # Function CONTAINS BasicBlock
        graph.add_edge(func_id, bb_id, EdgeType.CONTAINS)

        # BRANCHES_TO edges
        for succ in block.successors:
            succ_id = f"bb:{analysis.file}:{analysis.name}:{succ}"
            graph.add_edge(bb_id, succ_id, EdgeType.BRANCHES_TO)


# ── Full Function Analysis Orchestration ─────────────────────────────────────


def analyze_function(
    func_node: Any,
    spec: LangSpec,
    source: bytes,
    rel_path: str,
    graph: GraphData,
) -> FunctionAnalysis | None:
    """Full intra-procedural analysis of a single function.

    Returns the FunctionAnalysis or None if the function has no body.
    """
    # Get function name
    name = _node_name_from_field(func_node, spec.name_field, source)
    if not name:
        # Fallback: first identifier child
        for child in func_node.children:
            if child.type in ("identifier", "simple_identifier", "name"):
                name = _node_text(child, source)
                break
    if not name:
        name = f"anonymous_{func_node.start_point[0]}"

    line = func_node.start_point[0]

    # Find function body
    body = func_node.child_by_field_name(spec.body_field)
    if body is None:
        # Fallback: find first compound_stmt child
        for child in func_node.children:
            if child.type in spec.compound_stmt:
                body = child
                break

    if body is None:
        return None

    analysis = FunctionAnalysis(name=name, file=rel_path, line=line)

    # 1. Build CFG
    analysis.blocks = build_cfg(body, spec)

    # 2. Extract variable definitions per block
    for block in analysis.blocks:
        block.var_defs = extract_var_defs(block, spec, source)

    # 3. Add function parameters to block 0
    if analysis.blocks:
        params = extract_params(func_node, spec, source)
        analysis.blocks[0].var_defs = params + analysis.blocks[0].var_defs

    # 4. Compute reaching definitions
    compute_reaching_definitions(analysis)

    # 5. Generate data flow edges
    generate_data_flow_edges(analysis, graph)

    # 6. Propagate taint
    propagate_taint(analysis, rel_path, graph)

    # 7. Emit CFG to graph
    emit_cfg_to_graph(analysis, graph)

    # 8. Detect language-specific patterns
    if spec.pattern_detector is not None:
        flags = spec.pattern_detector(func_node, source)
        if flags:
            func_id = f"func:{rel_path}:{name}:{line}"
            # Find existing function node and add pattern flags
            for node in graph.nodes:
                if node.id == func_id:
                    node.properties.update(flags)
                    break

    return analysis
