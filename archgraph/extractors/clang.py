"""Clang deep analysis extractor — Phase 2.

Provides intra-procedural semantic analysis for C/C++ using libclang:
- CFG (BasicBlock nodes + BRANCHES_TO edges)
- Data flow (variable def/use chains → DATA_FLOWS_TO edges)
- Taint tracking (INPUT_SOURCE → variable chain → DANGEROUS_SINK → TAINTS edges)
- Type resolution (typedef chain unwinding)
- Macro expansion tracking (EXPANDS_MACRO edges)
- Pointer annotations (void* cast, pointer arithmetic flags)

Tree-sitter already handles structural extraction (functions, classes, CALLS, IMPORTS).
This module adds only the semantic layer on top.

Requires: libclang (pip install libclang>=18.1.0)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from archgraph.config import (
    DANGEROUS_SINKS,
    EXTENSION_MAP,
    INPUT_SOURCES,
    SKIP_DIRS,
    SKIP_FILES,
)
from archgraph.extractors.base import BaseExtractor
from archgraph.graph.schema import EdgeType, GraphData, NodeLabel

logger = logging.getLogger(__name__)

# C/C++ file extensions handled by this extractor
_C_EXTENSIONS = frozenset({".c", ".h", ".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"})


# ── Private data structures ──────────────────────────────────────────────────


@dataclass
class _VarDef:
    """A single variable definition (declaration or assignment)."""

    name: str
    line: int
    rhs_vars: list[str] = field(default_factory=list)
    rhs_calls: list[str] = field(default_factory=list)
    is_param: bool = False


@dataclass
class _BasicBlock:
    """A basic block in a function's CFG."""

    index: int
    stmts: list[Any] = field(default_factory=list)  # clang cursors
    var_defs: list[_VarDef] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)


@dataclass
class _FunctionAnalysis:
    """Results of analyzing a single function."""

    name: str
    file: str
    line: int
    blocks: list[_BasicBlock] = field(default_factory=list)
    reaching_in: dict[int, set[tuple[str, int]]] = field(default_factory=dict)
    reaching_out: dict[int, set[tuple[str, int]]] = field(default_factory=dict)


# ── ClangExtractor ───────────────────────────────────────────────────────────


class ClangExtractor(BaseExtractor):
    """Deep C/C++ analysis using libclang."""

    def __init__(
        self,
        compile_commands: Path | None = None,
        extra_args: list[str] | None = None,
    ) -> None:
        self._available = False
        self._ci = None  # clang.cindex module
        self._compile_db: dict[str, list[str]] | None = None
        self._compile_commands_path = compile_commands
        self._extra_args = extra_args or []

        try:
            import clang.cindex as ci

            self._ci = ci
            self._available = True
        except ImportError:
            logger.info(
                "libclang not available. Install with: pip install 'archgraph[clang]'"
            )

    @property
    def available(self) -> bool:
        return self._available

    def extract(self, repo_path: Path, **kwargs: object) -> GraphData:
        """Extract deep analysis data from C/C++ source files."""
        if not self._available:
            logger.warning("Clang extractor not available — skipping deep analysis")
            return GraphData()

        graph = GraphData()
        repo = repo_path.resolve()

        # Load compile_commands.json if available
        self._compile_db = self._load_compile_db(repo)

        files = self._collect_files(repo)
        if not files:
            logger.info("No C/C++ files found for clang analysis")
            return graph

        logger.info("Clang deep analysis: %d C/C++ files", len(files))

        for fpath in files:
            try:
                self._analyze_file(fpath, repo, graph)
            except Exception:
                logger.debug("Clang analysis failed for %s", fpath, exc_info=True)

        return graph

    # ── File collection ──────────────────────────────────────────────────

    def _collect_files(self, repo: Path) -> list[Path]:
        """Collect C/C++ files, respecting SKIP_DIRS/SKIP_FILES."""
        files: list[Path] = []
        for root, dirs, filenames in os.walk(repo):
            # Filter out skipped directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                if fname in SKIP_FILES:
                    continue
                fpath = Path(root) / fname
                if fpath.suffix.lower() in _C_EXTENSIONS:
                    files.append(fpath)
        return sorted(files)

    # ── Compile commands ─────────────────────────────────────────────────

    def _load_compile_db(self, repo: Path) -> dict[str, list[str]] | None:
        """Load compile_commands.json if it exists. Returns file→args mapping."""
        cc_path = self._compile_commands_path
        if cc_path is None:
            # Search common locations
            for candidate in [
                repo / "compile_commands.json",
                repo / "build" / "compile_commands.json",
            ]:
                if candidate.exists():
                    cc_path = candidate
                    break

        if cc_path is None or not cc_path.exists():
            return None

        try:
            data = json.loads(cc_path.read_text(encoding="utf-8"))
            db: dict[str, list[str]] = {}
            for entry in data:
                filepath = entry.get("file", "")
                cmd = entry.get("command", "")
                arguments = entry.get("arguments", [])
                if arguments:
                    # Filter out compiler and source file
                    args = [a for a in arguments[1:] if a != filepath]
                else:
                    parts = cmd.split()
                    args = [a for a in parts[1:] if a != filepath]
                db[filepath] = args
            logger.info("Loaded compile_commands.json with %d entries", len(db))
            return db
        except Exception:
            logger.debug("Failed to load compile_commands.json", exc_info=True)
            return None

    def _get_compile_args(self, fpath: Path) -> list[str]:
        """Get compile arguments for a file."""
        args: list[str] = []

        # From compile_commands.json
        if self._compile_db:
            file_args = self._compile_db.get(str(fpath), [])
            if file_args:
                args.extend(file_args)

        # Language standard
        suffix = fpath.suffix.lower()
        if suffix in (".c", ".h"):
            args.append("-std=c11")
        elif suffix in (".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"):
            args.append("-std=c++17")

        # Add include path for the file's directory
        args.append(f"-I{fpath.parent}")

        # Extra user args
        args.extend(self._extra_args)

        return args

    # ── File analysis ────────────────────────────────────────────────────

    def _analyze_file(self, fpath: Path, repo: Path, graph: GraphData) -> None:
        """Parse and analyze a single file."""
        ci = self._ci
        args = self._get_compile_args(fpath)
        index = ci.Index.create()

        tu = index.parse(
            str(fpath),
            args=args,
            options=ci.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )

        if tu is None:
            logger.debug("Failed to parse %s", fpath)
            return

        rel_path = str(fpath.relative_to(repo)) if fpath.is_relative_to(repo) else str(fpath)

        # Walk the AST
        for cursor in tu.cursor.get_children():
            # Only process cursors from this file
            if cursor.location.file is None or Path(cursor.location.file.name) != fpath:
                continue

            kind = cursor.kind

            # Function definitions → deep analysis
            if kind in (
                ci.CursorKind.FUNCTION_DECL,
                ci.CursorKind.CXX_METHOD,
            ) and cursor.is_definition():
                self._analyze_function(cursor, rel_path, graph)

            # Typedef → type resolution
            elif kind == ci.CursorKind.TYPEDEF_DECL:
                self._process_typedef(cursor, rel_path, graph)

            # Macro instantiation → EXPANDS_MACRO
            elif kind == ci.CursorKind.MACRO_INSTANTIATION:
                self._process_macro_usage(cursor, rel_path, graph)

    # ── Function analysis orchestration ──────────────────────────────────

    def _analyze_function(self, cursor: Any, rel_path: str, graph: GraphData) -> None:
        """Full intra-procedural analysis of a single function."""
        ci = self._ci
        name = cursor.spelling
        line = cursor.location.line

        # Find the compound statement (function body)
        body = None
        for child in cursor.get_children():
            if child.kind == ci.CursorKind.COMPOUND_STMT:
                body = child
                break

        if body is None:
            return

        analysis = _FunctionAnalysis(name=name, file=rel_path, line=line)

        # 1. Build CFG
        self._build_cfg(body, analysis)

        # 2. Extract variable definitions per block
        for block in analysis.blocks:
            block.var_defs = self._extract_var_defs(block, cursor)

        # 3. Add function parameters to block 0
        if analysis.blocks:
            params = self._extract_params(cursor)
            analysis.blocks[0].var_defs = params + analysis.blocks[0].var_defs

        # 4. Compute reaching definitions
        self._compute_reaching_definitions(analysis)

        # 5. Generate data flow edges
        self._generate_data_flow_edges(analysis, graph)

        # 6. Propagate taint
        self._propagate_taint(analysis, rel_path, graph)

        # 7. Emit CFG to graph
        self._emit_cfg_to_graph(analysis, graph)

        # 8. Annotate pointer patterns
        self._annotate_pointer_patterns(cursor, rel_path, name, line, graph)

    # ── CFG builder ──────────────────────────────────────────────────────

    def _build_cfg(self, body: Any, analysis: _FunctionAnalysis) -> None:
        """Build a control flow graph from the function body."""
        # Start with block 0
        blocks: list[_BasicBlock] = [_BasicBlock(index=0)]
        self._decompose_stmts(body, blocks, current_idx=0)
        analysis.blocks = blocks

        # Compute predecessors from successors
        for block in blocks:
            for succ in block.successors:
                if succ < len(blocks):
                    blocks[succ].predecessors.append(block.index)

    def _decompose_stmts(
        self,
        node: Any,
        blocks: list[_BasicBlock],
        current_idx: int,
    ) -> int:
        """Recursively decompose statements into basic blocks. Returns the exit block index."""
        ci = self._ci

        for child in node.get_children():
            kind = child.kind

            if kind == ci.CursorKind.IF_STMT:
                current_idx = self._handle_if(child, blocks, current_idx)

            elif kind in (ci.CursorKind.WHILE_STMT, ci.CursorKind.FOR_STMT):
                current_idx = self._handle_loop(child, blocks, current_idx)

            elif kind == ci.CursorKind.RETURN_STMT:
                blocks[current_idx].stmts.append(child)
                # Return terminates the block — no successors
                return current_idx

            elif kind == ci.CursorKind.COMPOUND_STMT:
                current_idx = self._decompose_stmts(child, blocks, current_idx)

            else:
                blocks[current_idx].stmts.append(child)

        return current_idx

    def _handle_if(self, node: Any, blocks: list[_BasicBlock], current_idx: int) -> int:
        """Handle if/else: current→then, current→else, both→join."""
        ci = self._ci
        children = list(node.get_children())

        # Condition is first child — add to current block
        if children:
            blocks[current_idx].stmts.append(children[0])

        # Then block
        then_idx = len(blocks)
        blocks.append(_BasicBlock(index=then_idx))
        blocks[current_idx].successors.append(then_idx)

        then_exit = then_idx
        if len(children) > 1:
            then_body = children[1]
            if then_body.kind == ci.CursorKind.COMPOUND_STMT:
                then_exit = self._decompose_stmts(then_body, blocks, then_idx)
            else:
                blocks[then_idx].stmts.append(then_body)

        # Else block (if present)
        else_exit = current_idx
        if len(children) > 2:
            else_idx = len(blocks)
            blocks.append(_BasicBlock(index=else_idx))
            blocks[current_idx].successors.append(else_idx)

            else_body = children[2]
            if else_body.kind == ci.CursorKind.COMPOUND_STMT:
                else_exit = self._decompose_stmts(else_body, blocks, else_idx)
            elif else_body.kind == ci.CursorKind.IF_STMT:
                # else if chain
                else_exit = self._handle_if(else_body, blocks, else_idx)
            else:
                blocks[else_idx].stmts.append(else_body)
                else_exit = else_idx
        else:
            # No else — current also flows to join directly
            else_exit = current_idx

        # Join block
        join_idx = len(blocks)
        blocks.append(_BasicBlock(index=join_idx))
        if then_exit < len(blocks):
            blocks[then_exit].successors.append(join_idx)
        if else_exit < len(blocks) and else_exit != current_idx:
            blocks[else_exit].successors.append(join_idx)
        elif else_exit == current_idx:
            blocks[current_idx].successors.append(join_idx)

        return join_idx

    def _handle_loop(self, node: Any, blocks: list[_BasicBlock], current_idx: int) -> int:
        """Handle while/for loops: current→header→body→header, header→exit."""
        ci = self._ci
        children = list(node.get_children())

        # Header block (loop condition)
        header_idx = len(blocks)
        blocks.append(_BasicBlock(index=header_idx))
        blocks[current_idx].successors.append(header_idx)

        # Add condition to header
        if children:
            blocks[header_idx].stmts.append(children[0])

        # Body block
        body_idx = len(blocks)
        blocks.append(_BasicBlock(index=body_idx))
        blocks[header_idx].successors.append(body_idx)

        # Process loop body
        body_exit = body_idx
        body_node = children[-1] if children else None
        if body_node and body_node.kind == ci.CursorKind.COMPOUND_STMT:
            body_exit = self._decompose_stmts(body_node, blocks, body_idx)
        elif body_node:
            blocks[body_idx].stmts.append(body_node)

        # Back edge: body→header
        blocks[body_exit].successors.append(header_idx)

        # Exit block
        exit_idx = len(blocks)
        blocks.append(_BasicBlock(index=exit_idx))
        blocks[header_idx].successors.append(exit_idx)

        return exit_idx

    # ── Variable definition extraction ───────────────────────────────────

    def _extract_var_defs(self, block: _BasicBlock, func_cursor: Any) -> list[_VarDef]:
        """Extract variable definitions from a basic block's statements."""
        ci = self._ci
        defs: list[_VarDef] = []

        for stmt in block.stmts:
            self._walk_for_defs(stmt, defs, ci)

        return defs

    def _walk_for_defs(self, node: Any, defs: list[_VarDef], ci: Any) -> None:
        """Walk AST node to find variable definitions and assignments."""
        kind = node.kind

        if kind == ci.CursorKind.VAR_DECL:
            rhs_vars: list[str] = []
            rhs_calls: list[str] = []
            # Walk initializer
            for child in node.get_children():
                self._walk_expr(child, rhs_vars, rhs_calls, ci)
            defs.append(_VarDef(
                name=node.spelling,
                line=node.location.line,
                rhs_vars=rhs_vars,
                rhs_calls=rhs_calls,
            ))

        elif kind == ci.CursorKind.BINARY_OPERATOR:
            # Check if this is an assignment
            tokens = list(node.get_tokens())
            is_assignment = False
            lhs_name = ""
            for i, tok in enumerate(tokens):
                if tok.spelling == "=" and (i == 0 or tokens[i - 1].spelling not in ("!", "=", "<", ">", "+")):
                    is_assignment = True
                    break

            if is_assignment:
                children = list(node.get_children())
                if children:
                    lhs = children[0]
                    if lhs.kind == ci.CursorKind.DECL_REF_EXPR:
                        lhs_name = lhs.spelling
                    elif lhs.kind == ci.CursorKind.MEMBER_REF_EXPR:
                        lhs_name = lhs.spelling

                if lhs_name:
                    rhs_vars: list[str] = []
                    rhs_calls: list[str] = []
                    if len(children) > 1:
                        self._walk_expr(children[1], rhs_vars, rhs_calls, ci)
                    defs.append(_VarDef(
                        name=lhs_name,
                        line=node.location.line,
                        rhs_vars=rhs_vars,
                        rhs_calls=rhs_calls,
                    ))

        else:
            for child in node.get_children():
                self._walk_for_defs(child, defs, ci)

    def _walk_expr(
        self, node: Any, vars_out: list[str], calls_out: list[str], ci: Any
    ) -> None:
        """Walk an expression collecting variable references and function calls."""
        kind = node.kind

        if kind == ci.CursorKind.DECL_REF_EXPR:
            vars_out.append(node.spelling)
        elif kind == ci.CursorKind.CALL_EXPR:
            calls_out.append(node.spelling)
            # Also walk arguments for nested refs
            for child in node.get_children():
                self._walk_expr(child, vars_out, calls_out, ci)
            return
        elif kind == ci.CursorKind.MEMBER_REF_EXPR:
            vars_out.append(node.spelling)

        for child in node.get_children():
            self._walk_expr(child, vars_out, calls_out, ci)

    def _extract_params(self, func_cursor: Any) -> list[_VarDef]:
        """Extract function parameters as _VarDef entries."""
        ci = self._ci
        params: list[_VarDef] = []
        for child in func_cursor.get_children():
            if child.kind == ci.CursorKind.PARM_DECL:
                params.append(_VarDef(
                    name=child.spelling,
                    line=child.location.line,
                    is_param=True,
                ))
        return params

    # ── Reaching definitions (iterative worklist) ────────────────────────

    def _compute_reaching_definitions(self, analysis: _FunctionAnalysis) -> None:
        """Classic iterative worklist reaching definitions algorithm."""
        blocks = analysis.blocks
        n = len(blocks)
        if n == 0:
            return

        # gen[b] = set of (var, line) defined in block b (last def wins)
        # kill[b] = set of (var, *) killed by definitions in block b
        gen: dict[int, set[tuple[str, int]]] = {}
        kill_vars: dict[int, set[str]] = {}  # var names killed per block

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

            # OUT[b] = gen[b] ∪ (IN[b] - kill[b])
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

    # ── Data flow edge generation ────────────────────────────────────────

    def _generate_data_flow_edges(self, analysis: _FunctionAnalysis, graph: GraphData) -> None:
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

    # ── Taint propagation ────────────────────────────────────────────────

    def _propagate_taint(
        self, analysis: _FunctionAnalysis, rel_path: str, graph: GraphData
    ) -> None:
        """Propagate taint from INPUT_SOURCES through variable chains to DANGEROUS_SINKS."""
        # Build var→def mapping across all blocks
        all_defs: list[_VarDef] = []
        for block in analysis.blocks:
            all_defs.extend(block.var_defs)

        # Find initially tainted variables (assigned from input source calls)
        tainted_vars: set[str] = set()
        for vd in all_defs:
            for call in vd.rhs_calls:
                if call in INPUT_SOURCES or self._basename_match(call, INPUT_SOURCES):
                    tainted_vars.add(vd.name)

        # Also mark parameters as tainted if they're input sources (e.g., named input/buf)
        # Parameters are always potentially tainted in a security analysis
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
                if call in DANGEROUS_SINKS or self._basename_match(call, DANGEROUS_SINKS):
                    # Check if any RHS var is tainted
                    if any(rv in tainted_vars for rv in vd.rhs_vars):
                        # Find the source — first input source call in the chain
                        source_call = self._find_taint_source(vd, all_defs, tainted_vars)
                        source_id = f"funcref:{rel_path}:{source_call}:0"
                        sink_id = f"funcref:{rel_path}:{call}:0"
                        graph.add_edge(
                            source_id,
                            sink_id,
                            EdgeType.TAINTS,
                            via_function=analysis.name,
                            via_variable=",".join(rv for rv in vd.rhs_vars if rv in tainted_vars),
                            file=rel_path,
                        )

        # Also check call arguments for taint
        self._check_call_args_taint(analysis, all_defs, tainted_vars, rel_path, graph)

    def _check_call_args_taint(
        self,
        analysis: _FunctionAnalysis,
        all_defs: list[_VarDef],
        tainted_vars: set[str],
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Check if tainted variables are passed as arguments to dangerous sinks."""
        ci = self._ci
        for block in analysis.blocks:
            for stmt in block.stmts:
                self._walk_for_tainted_calls(
                    stmt, tainted_vars, analysis, all_defs, rel_path, graph, ci
                )

    def _walk_for_tainted_calls(
        self,
        node: Any,
        tainted_vars: set[str],
        analysis: _FunctionAnalysis,
        all_defs: list[_VarDef],
        rel_path: str,
        graph: GraphData,
        ci: Any,
    ) -> None:
        """Walk AST looking for calls to dangerous sinks with tainted arguments."""
        if node.kind == ci.CursorKind.CALL_EXPR:
            call_name = node.spelling
            if call_name in DANGEROUS_SINKS or self._basename_match(call_name, DANGEROUS_SINKS):
                # Check arguments for tainted refs
                arg_vars: list[str] = []
                for arg in node.get_children():
                    if arg.kind == ci.CursorKind.DECL_REF_EXPR:
                        arg_vars.append(arg.spelling)
                    else:
                        # Walk deeper for refs
                        refs: list[str] = []
                        calls: list[str] = []
                        self._walk_expr(arg, refs, calls, ci)
                        arg_vars.extend(refs)

                tainted_args = [v for v in arg_vars if v in tainted_vars]
                if tainted_args:
                    source_call = self._find_taint_source_from_vars(
                        tainted_args, all_defs, tainted_vars
                    )
                    source_id = f"funcref:{rel_path}:{source_call}:0"
                    sink_id = f"funcref:{rel_path}:{call_name}:0"
                    # Only add if not already emitted
                    graph.add_edge(
                        source_id,
                        sink_id,
                        EdgeType.TAINTS,
                        via_function=analysis.name,
                        via_variable=",".join(tainted_args),
                        file=rel_path,
                    )

        for child in node.get_children():
            self._walk_for_tainted_calls(
                child, tainted_vars, analysis, all_defs, rel_path, graph, ci
            )

    def _find_taint_source(
        self, vd: _VarDef, all_defs: list[_VarDef], tainted_vars: set[str]
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
                        if call in INPUT_SOURCES or self._basename_match(call, INPUT_SOURCES):
                            return call
                    queue.extend(rv for rv in d.rhs_vars if rv in tainted_vars)

        # Fallback: return first known input source
        for d in all_defs:
            for call in d.rhs_calls:
                if call in INPUT_SOURCES or self._basename_match(call, INPUT_SOURCES):
                    return call
        return "unknown_source"

    def _find_taint_source_from_vars(
        self, tainted_args: list[str], all_defs: list[_VarDef], tainted_vars: set[str]
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
                        if call in INPUT_SOURCES or self._basename_match(call, INPUT_SOURCES):
                            return call
                    queue.extend(rv for rv in d.rhs_vars if rv in tainted_vars)

        return "unknown_source"

    def _basename_match(self, name: str, patterns: frozenset[str]) -> bool:
        """Check if a function name matches patterns (last segment check)."""
        base = name.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
        return base in patterns

    # ── CFG graph emission ───────────────────────────────────────────────

    def _emit_cfg_to_graph(self, analysis: _FunctionAnalysis, graph: GraphData) -> None:
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

    # ── Typedef resolution ───────────────────────────────────────────────

    def _process_typedef(self, cursor: Any, rel_path: str, graph: GraphData) -> None:
        """Resolve typedef chain and annotate TypeAlias node."""
        ci = self._ci
        name = cursor.spelling
        underlying = cursor.underlying_typedef_type

        # Walk the typedef chain to the final resolved type
        resolved = underlying.spelling if underlying else name

        # Try to follow canonical type
        try:
            canonical = underlying.get_canonical()
            if canonical:
                resolved = canonical.spelling
        except Exception:
            pass

        # Find existing TypeAlias node and add resolved_type property
        type_id = f"type:{rel_path}:{name}:{cursor.location.line}"
        for node in graph.nodes:
            if node.id == type_id:
                node.properties["resolved_type"] = resolved
                return

        # If no existing node (tree-sitter might not have created it), create one
        graph.add_node(
            type_id,
            NodeLabel.TYPE_ALIAS,
            name=name,
            file=rel_path,
            line_start=cursor.location.line,
            resolved_type=resolved,
        )

    # ── Macro usage tracking ─────────────────────────────────────────────

    def _process_macro_usage(self, cursor: Any, rel_path: str, graph: GraphData) -> None:
        """Track macro instantiation → EXPANDS_MACRO edge."""
        macro_name = cursor.spelling
        if not macro_name:
            return

        line = cursor.location.line

        # Find the enclosing function (walk up isn't easy with libclang, use parent heuristic)
        # Create edge from the file to the macro as a fallback
        file_id = f"file:{rel_path}"
        macro_id = f"macro:{rel_path}:{macro_name}:0"

        # Ensure macro node exists
        graph.add_node(
            macro_id,
            NodeLabel.MACRO,
            name=macro_name,
            file=rel_path,
        )

        graph.add_edge(
            file_id,
            macro_id,
            EdgeType.EXPANDS_MACRO,
            line=line,
        )

    # ── Pointer pattern annotations ──────────────────────────────────────

    def _annotate_pointer_patterns(
        self,
        func_cursor: Any,
        rel_path: str,
        func_name: str,
        func_line: int,
        graph: GraphData,
    ) -> None:
        """Detect void* casts and pointer arithmetic in a function."""
        ci = self._ci
        has_void_cast = False
        has_pointer_arith = False

        for descendant in self._walk_all(func_cursor):
            kind = descendant.kind

            # C-style cast to/from void*
            if kind == ci.CursorKind.CSTYLE_CAST_EXPR:
                cast_type = descendant.type.spelling if descendant.type else ""
                if "void *" in cast_type or "void*" in cast_type:
                    has_void_cast = True

            # Pointer arithmetic: array subscript on pointer or + on pointer
            elif kind == ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                has_pointer_arith = True

        if has_void_cast or has_pointer_arith:
            func_id = f"func:{rel_path}:{func_name}:{func_line}"
            for node in graph.nodes:
                if node.id == func_id:
                    if has_void_cast:
                        node.properties["has_void_cast"] = True
                    if has_pointer_arith:
                        node.properties["has_pointer_arith"] = True
                    return

    def _walk_all(self, cursor: Any) -> list[Any]:
        """Recursively collect all descendant cursors."""
        result: list[Any] = []
        for child in cursor.get_children():
            result.append(child)
            result.extend(self._walk_all(child))
        return result
