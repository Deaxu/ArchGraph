"""Tree-sitter based multi-language source code extractor."""

from __future__ import annotations

import hashlib
import importlib
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import tree_sitter as ts

from archgraph.config import EXTENSION_MAP, LANGUAGE_MODULES, SKIP_DIRS, SKIP_FILES
from archgraph.extractors.base import BaseExtractor
from archgraph.graph.schema import GraphData, NodeLabel, EdgeType

logger = logging.getLogger(__name__)


# ── Per-language AST query definitions ──────────────────────────────────────
# Each language maps node types to extractor logic. We use tree-sitter node
# kind names which differ across grammars.

# Maps language -> dict of AST node types used for each concept
_LANG_NODE_TYPES: dict[str, dict[str, list[str]]] = {
    "c": {
        "function_def": ["function_definition"],
        "function_decl": ["declaration"],
        "struct": ["struct_specifier"],
        "enum": ["enum_specifier"],
        "typedef": ["type_definition"],
        "macro": ["preproc_def", "preproc_function_def"],
        "include": ["preproc_include"],
        "call": ["call_expression"],
        "field_decl": ["field_declaration"],
    },
    "cpp": {
        "function_def": ["function_definition"],
        "class": ["class_specifier"],
        "struct": ["struct_specifier"],
        "enum": ["enum_specifier"],
        "typedef": ["type_definition"],
        "macro": ["preproc_def", "preproc_function_def"],
        "include": ["preproc_include"],
        "call": ["call_expression"],
        "field_decl": ["field_declaration"],
        "namespace": ["namespace_definition"],
        "template": ["template_declaration"],
    },
    "rust": {
        "function_def": ["function_item"],
        "struct": ["struct_item"],
        "enum": ["enum_item"],
        "trait": ["trait_item"],
        "impl": ["impl_item"],
        "type_alias": ["type_item"],
        "macro": ["macro_definition"],
        "use": ["use_declaration"],
        "call": ["call_expression"],
        "field_decl": ["field_declaration"],
        "mod": ["mod_item"],
    },
    "java": {
        "function_def": ["method_declaration", "constructor_declaration"],
        "class": ["class_declaration"],
        "interface": ["interface_declaration"],
        "enum": ["enum_declaration"],
        "import": ["import_declaration"],
        "call": ["method_invocation"],
        "field_decl": ["field_declaration"],
    },
    "kotlin": {
        "function_def": ["function_declaration"],
        "class": ["class_declaration"],
        "interface": ["interface_declaration"],  # not always present
        "enum": ["enum_class_body"],
        "import": ["import_header"],
        "call": ["call_expression"],
    },
    "go": {
        "function_def": ["function_declaration", "method_declaration"],
        "struct": ["type_declaration"],
        "interface": ["type_declaration"],
        "import": ["import_declaration"],
        "call": ["call_expression"],
        "field_decl": ["field_declaration"],
    },
    "javascript": {
        "function_def": [
            "function_declaration",
            "method_definition",
            "arrow_function",
        ],
        "class": ["class_declaration"],
        "import": ["import_statement"],
        "call": ["call_expression"],
    },
    "typescript": {
        "function_def": [
            "function_declaration",
            "method_definition",
            "arrow_function",
        ],
        "class": ["class_declaration"],
        "interface": ["interface_declaration"],
        "type_alias": ["type_alias_declaration"],
        "enum": ["enum_declaration"],
        "import": ["import_statement"],
        "call": ["call_expression"],
    },
    "swift": {
        "function_def": ["function_declaration"],
        "class": ["class_declaration"],
        "struct": ["struct_declaration"],
        "enum": ["enum_declaration"],
        "protocol": ["protocol_declaration"],
        "import": ["import_declaration"],
        "call": ["call_expression"],
    },
    "objc": {
        "function_def": ["function_definition", "method_definition"],
        "class": ["class_interface", "class_implementation"],
        "import": ["preproc_import"],
        "call": ["message_expression"],
    },
}


def _file_hash(path: Path) -> str:
    """Compute SHA-256 of file contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _node_text(node: ts.Node, source: bytes) -> str:
    """Get the text of a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _iter_descendants(node: ts.Node) -> list[ts.Node]:
    """Iterate all descendant nodes."""
    result: list[ts.Node] = []
    for child in node.children:
        result.append(child)
        result.extend(_iter_descendants(child))
    return result


_BODY_COMPOUND_TYPES = frozenset({
    "compound_statement", "block", "function_body",
    "statement_block", "class_body", "declaration_list",
})


def _find_child_by_type(node: ts.Node, *types: str) -> ts.Node | None:
    """Find the first child of node matching one of the given types."""
    for child in node.children:
        if child.type in types:
            return child
    return None


def _find_child_by_field(node: ts.Node, field_name: str) -> ts.Node | None:
    """Find a child by field name."""
    return node.child_by_field_name(field_name)


class TreeSitterExtractor(BaseExtractor):
    """Extracts code structure using tree-sitter grammars."""

    def __init__(
        self,
        languages: list[str] | None = None,
        include_body: bool = True,
        max_body_size: int = 51_200,
    ) -> None:
        self._languages = languages or ["c", "cpp", "rust", "java", "go"]
        self._include_body = include_body
        self._max_body_size = max_body_size
        self._parsers: dict[str, ts.Parser] = {}
        self._ts_languages: dict[str, ts.Language] = {}
        self._thread_local = threading.local()
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Initialize tree-sitter parsers for each requested language."""
        for lang in self._languages:
            module_name = LANGUAGE_MODULES.get(lang)
            if not module_name:
                logger.warning("No tree-sitter module for language: %s", lang)
                continue
            try:
                mod = importlib.import_module(module_name)
                # tree-sitter 0.24+ API: language() returns a Language capsule
                # TypeScript module exposes language_typescript()/language_tsx()
                if hasattr(mod, "language"):
                    lang_func = mod.language
                elif hasattr(mod, f"language_{lang}"):
                    lang_func = getattr(mod, f"language_{lang}")
                elif hasattr(mod, "language_typescript") and lang == "typescript":
                    lang_func = mod.language_typescript
                else:
                    raise AttributeError(f"No language function found in {module_name}")
                ts_lang = ts.Language(lang_func())
                parser = ts.Parser(ts_lang)
                self._parsers[lang] = parser
                self._ts_languages[lang] = ts_lang
                logger.debug("Initialized parser for %s", lang)
            except (ImportError, Exception) as e:
                logger.warning("Could not load tree-sitter grammar for %s: %s", lang, e)

    def _get_thread_parser(self, lang: str) -> ts.Parser:
        """Get a thread-local parser for the given language."""
        parsers = getattr(self._thread_local, "parsers", None)
        if parsers is None:
            parsers = {}
            self._thread_local.parsers = parsers
        if lang not in parsers:
            ts_lang = self._ts_languages[lang]
            parsers[lang] = ts.Parser(ts_lang)
        return parsers[lang]

    def _truncate_body(self, text: str) -> tuple[str, bool]:
        """Truncate body if it exceeds max_body_size. Returns (text, was_truncated)."""
        encoded = text.encode("utf-8")
        if len(encoded) <= self._max_body_size:
            return text, False
        truncated = encoded[:self._max_body_size]
        last_nl = truncated.rfind(b"\n")
        if last_nl > 0:
            truncated = truncated[:last_nl]
        total_lines = text.count("\n") + 1
        decoded = truncated.decode("utf-8", errors="replace")
        decoded += f"\n// ... [truncated: {total_lines} total lines]"
        return decoded, True

    def extract(self, repo_path: Path, **kwargs: object) -> GraphData:
        """Extract graph from all supported source files in the repo."""
        workers = kwargs.get("workers", 1)
        changed_files: set[str] | None = kwargs.get("changed_files", None)  # type: ignore[assignment]
        files = self._collect_files(repo_path, changed_files=changed_files)
        logger.info("Found %d source files to parse", len(files))

        file_langs = [
            (f, self._detect_language(f))
            for f in files
            if self._detect_language(f) in self._parsers
        ]

        if workers and workers > 1 and len(file_langs) > 1:
            return self._extract_parallel(file_langs, repo_path, workers)

        graph = GraphData()
        for file_path, lang in file_langs:
            try:
                self._extract_file(file_path, lang, repo_path, graph)
            except Exception:
                logger.exception("Error extracting %s", file_path)
        return graph

    def _extract_parallel(
        self, file_langs: list[tuple[Path, str]], repo_path: Path, workers: int
    ) -> GraphData:
        """Parse files in parallel using ThreadPoolExecutor."""
        graph = GraphData()

        def _process(args: tuple[Path, str]) -> GraphData:
            fpath, lang = args
            return self._extract_file_to_graph(fpath, lang, repo_path)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for sub_graph in pool.map(_process, file_langs):
                graph.merge(sub_graph)

        return graph

    def _extract_file_to_graph(
        self, file_path: Path, lang: str, repo_path: Path
    ) -> GraphData:
        """Parse a single file and return its own GraphData (thread-safe)."""
        graph = GraphData()
        try:
            source = file_path.read_bytes()
            rel_path = str(file_path.relative_to(repo_path))
            parser = self._get_thread_parser(lang)
            tree = parser.parse(source)
            root = tree.root_node

            lines = source.count(b"\n") + 1
            file_id = f"file:{rel_path}"
            graph.add_node(
                file_id,
                NodeLabel.FILE,
                path=rel_path,
                language=lang,
                size=len(source),
                hash=_file_hash(file_path),
                lines=lines,
            )

            lang_types = _LANG_NODE_TYPES.get(lang, {})
            self._walk_tree(root, source, lang, lang_types, file_id, rel_path, graph)
        except Exception:
            logger.exception("Error extracting %s", file_path)
        return graph

    def _collect_files(
        self, repo_path: Path, changed_files: set[str] | None = None
    ) -> list[Path]:
        """Collect all source files, respecting skip lists.

        If *changed_files* is given, only include files whose repo-relative
        path is in the set.
        """
        files: list[Path] = []
        for path in repo_path.rglob("*"):
            if not path.is_file():
                continue
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            if path.name in SKIP_FILES:
                continue
            if path.suffix in EXTENSION_MAP:
                if changed_files is not None:
                    rel = str(path.relative_to(repo_path))
                    if rel not in changed_files:
                        continue
                files.append(path)
        return sorted(files)

    def _detect_language(self, path: Path) -> str:
        """Detect language from file extension."""
        return EXTENSION_MAP.get(path.suffix, "")

    def _extract_file(
        self,
        file_path: Path,
        lang: str,
        repo_path: Path,
        graph: GraphData,
    ) -> None:
        """Parse a single file and add its nodes/edges to the graph."""
        source = file_path.read_bytes()
        rel_path = str(file_path.relative_to(repo_path))

        # Parse
        parser = self._parsers[lang]
        tree = parser.parse(source)
        root = tree.root_node

        # File node
        lines = source.count(b"\n") + 1
        file_id = f"file:{rel_path}"
        graph.add_node(
            file_id,
            NodeLabel.FILE,
            path=rel_path,
            language=lang,
            size=len(source),
            hash=_file_hash(file_path),
            lines=lines,
        )

        # Extract based on language node types
        lang_types = _LANG_NODE_TYPES.get(lang, {})
        self._walk_tree(root, source, lang, lang_types, file_id, rel_path, graph)

    def _walk_tree(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        lang_types: dict[str, list[str]],
        file_id: str,
        rel_path: str,
        graph: GraphData,
        parent_id: str | None = None,
    ) -> None:
        """Recursively walk the AST and extract nodes and edges."""
        node_type = node.type

        # --- Functions ---
        if node_type in lang_types.get("function_def", []):
            func_id = self._extract_function(node, source, lang, file_id, rel_path, graph)
            container = parent_id or file_id
            graph.add_edge(container, func_id, EdgeType.CONTAINS)
            # Recurse into function body for calls
            self._extract_calls_from(node, source, lang, lang_types, func_id, rel_path, graph)
            return  # Don't recurse further for children — calls handled above

        # --- Classes ---
        if node_type in lang_types.get("class", []):
            cls_id = self._extract_class(node, source, lang, file_id, rel_path, graph)
            graph.add_edge(file_id, cls_id, EdgeType.CONTAINS)
            # Recurse into class body
            for child in node.children:
                self._walk_tree(
                    child, source, lang, lang_types, file_id, rel_path, graph, parent_id=cls_id
                )
            return

        # --- Structs ---
        if node_type in lang_types.get("struct", []):
            struct_id = self._extract_struct(node, source, lang, file_id, rel_path, graph)
            graph.add_edge(file_id, struct_id, EdgeType.CONTAINS)
            # Extract fields
            self._extract_fields(node, source, struct_id, graph)
            return

        # --- Enums ---
        if node_type in lang_types.get("enum", []):
            self._extract_enum(node, source, lang, file_id, rel_path, graph)
            return

        # --- Interfaces / Traits / Protocols ---
        for key in ("interface", "trait", "protocol"):
            if node_type in lang_types.get(key, []):
                self._extract_interface(node, source, lang, file_id, rel_path, graph)
                return

        # --- Type aliases ---
        if node_type in lang_types.get("type_alias", []) or node_type in lang_types.get(
            "typedef", []
        ):
            self._extract_type_alias(node, source, lang, file_id, rel_path, graph)
            return

        # --- Macros ---
        if node_type in lang_types.get("macro", []):
            self._extract_macro(node, source, lang, file_id, rel_path, graph)
            return

        # --- Imports / Includes ---
        for key in ("include", "import", "use"):
            if node_type in lang_types.get(key, []):
                self._extract_import(node, source, file_id, rel_path, graph)
                return

        # --- Impl blocks (Rust) ---
        if node_type in lang_types.get("impl", []):
            self._extract_impl(node, source, lang, lang_types, file_id, rel_path, graph)
            return

        # Recurse
        for child in node.children:
            self._walk_tree(child, source, lang, lang_types, file_id, rel_path, graph, parent_id)

    # ── Node extractors ─────────────────────────────────────────────────────

    def _extract_function(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> str:
        """Extract a function/method node. Returns its node ID."""
        name = self._get_function_name(node, source, lang)
        func_id = f"func:{rel_path}:{name}:{node.start_point[0]}"

        # Try to extract parameters
        params = self._get_function_params(node, source, lang)
        return_type = self._get_function_return_type(node, source, lang)

        # Visibility / export check
        text = _node_text(node, source)
        is_exported = self._is_exported(text, lang)

        props: dict[str, Any] = dict(
            name=name,
            file=rel_path,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            params=params,
            return_type=return_type,
            is_exported=is_exported,
        )

        if self._include_body:
            body_text = _node_text(node, source)
            body_text, truncated = self._truncate_body(body_text)
            props["body"] = body_text
            props["body_lines"] = body_text.count("\n") + 1
            if truncated:
                props["body_truncated"] = True

        graph.add_node(func_id, NodeLabel.FUNCTION, **props)

        # Extract parameters as nodes
        self._extract_parameters(node, source, lang, func_id, graph)

        return func_id

    def _extract_class(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> str:
        """Extract a class node. Returns its node ID."""
        name = self._get_name(node, source, lang)
        cls_id = f"class:{rel_path}:{name}"

        text = _node_text(node, source)
        is_abstract = "abstract" in text.split("{")[0] if "{" in text else "abstract" in text

        graph.add_node(
            cls_id,
            NodeLabel.CLASS,
            name=name,
            file=rel_path,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            is_abstract=is_abstract,
        )

        if self._include_body:
            lang_types = _LANG_NODE_TYPES.get(lang, {})
            shell = self._extract_class_shell(node, source, lang, lang_types)
            shell, truncated = self._truncate_body(shell)
            graph.nodes[-1].properties["body"] = shell
            graph.nodes[-1].properties["body_lines"] = shell.count("\n") + 1
            if truncated:
                graph.nodes[-1].properties["body_truncated"] = True

        # Extract inheritance
        self._extract_inheritance(node, source, lang, cls_id, rel_path, graph)

        return cls_id

    def _extract_class_shell(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        lang_types: dict[str, list[str]],
    ) -> str:
        """Extract class source with method bodies replaced by { ... }."""
        class_bytes = bytearray(source[node.start_byte:node.end_byte])
        offset = node.start_byte

        func_types = lang_types.get("function_def", [])
        replacements: list[tuple[int, int]] = []

        for desc in _iter_descendants(node):
            if desc.type not in func_types:
                continue
            body = desc.child_by_field_name("body")
            if body is None:
                for child in desc.children:
                    if child.type in _BODY_COMPOUND_TYPES:
                        body = child
                        break
            if body is None:
                continue
            inner_start = body.start_byte + 1 - offset
            inner_end = body.end_byte - 1 - offset
            if inner_start < inner_end:
                replacements.append((inner_start, inner_end))

        for start, end in sorted(replacements, reverse=True):
            class_bytes[start:end] = b" ... "

        return class_bytes.decode("utf-8", errors="replace")

    def _extract_struct(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> str:
        """Extract a struct node."""
        name = self._get_name(node, source, lang)
        struct_id = f"struct:{rel_path}:{name}"

        graph.add_node(
            struct_id,
            NodeLabel.STRUCT,
            name=name,
            file=rel_path,
            line_start=node.start_point[0] + 1,
        )
        if self._include_body:
            body_text = _node_text(node, source)
            body_text, truncated = self._truncate_body(body_text)
            graph.nodes[-1].properties["body"] = body_text
            graph.nodes[-1].properties["body_lines"] = body_text.count("\n") + 1
            if truncated:
                graph.nodes[-1].properties["body_truncated"] = True
        return struct_id

    def _extract_enum(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> str:
        name = self._get_name(node, source, lang)
        enum_id = f"enum:{rel_path}:{name}"
        graph.add_node(
            enum_id,
            NodeLabel.ENUM,
            name=name,
            file=rel_path,
        )
        if self._include_body:
            body_text = _node_text(node, source)
            body_text, truncated = self._truncate_body(body_text)
            graph.nodes[-1].properties["body"] = body_text
            graph.nodes[-1].properties["body_lines"] = body_text.count("\n") + 1
            if truncated:
                graph.nodes[-1].properties["body_truncated"] = True
        graph.add_edge(file_id, enum_id, EdgeType.CONTAINS)
        return enum_id

    def _extract_interface(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> str:
        name = self._get_name(node, source, lang)
        iface_id = f"interface:{rel_path}:{name}"
        graph.add_node(
            iface_id,
            NodeLabel.INTERFACE,
            name=name,
            file=rel_path,
        )
        if self._include_body:
            body_text = _node_text(node, source)
            body_text, truncated = self._truncate_body(body_text)
            graph.nodes[-1].properties["body"] = body_text
            graph.nodes[-1].properties["body_lines"] = body_text.count("\n") + 1
            if truncated:
                graph.nodes[-1].properties["body_truncated"] = True
        graph.add_edge(file_id, iface_id, EdgeType.CONTAINS)
        return iface_id

    def _extract_type_alias(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> str:
        name = self._get_name(node, source, lang)
        alias_id = f"typealias:{rel_path}:{name}"
        graph.add_node(
            alias_id,
            NodeLabel.TYPE_ALIAS,
            name=name,
            file=rel_path,
        )
        graph.add_edge(file_id, alias_id, EdgeType.CONTAINS)
        return alias_id

    def _extract_macro(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> str:
        name = self._get_macro_name(node, source)
        macro_id = f"macro:{rel_path}:{name}"
        body = _node_text(node, source)
        graph.add_node(
            macro_id,
            NodeLabel.MACRO,
            name=name,
            file=rel_path,
            body=body[:500],  # Truncate long macros
        )
        graph.add_edge(file_id, macro_id, EdgeType.CONTAINS)
        return macro_id

    def _extract_import(
        self,
        node: ts.Node,
        source: bytes,
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Extract an import/include edge."""
        text = _node_text(node, source).strip()
        # Store as a property on the IMPORTS edge — we resolve targets later
        import_target = self._parse_import_target(text)
        if import_target:
            target_id = f"module:{import_target}"
            # Create a module node (may be deduped later)
            graph.add_node(target_id, NodeLabel.MODULE, name=import_target)
            graph.add_edge(file_id, target_id, EdgeType.IMPORTS, raw=text)

    def _extract_impl(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        lang_types: dict[str, list[str]],
        file_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Extract a Rust impl block — link methods to the type."""
        # Get the type name from the impl
        type_node = _find_child_by_field(node, "type")
        type_name = _node_text(type_node, source) if type_node else "unknown"
        type_id = f"struct:{rel_path}:{type_name}"

        # Check for trait impl
        trait_node = _find_child_by_field(node, "trait")
        if trait_node:
            trait_name = _node_text(trait_node, source)
            trait_id = f"interface:{rel_path}:{trait_name}"
            graph.add_node(trait_id, NodeLabel.INTERFACE, name=trait_name, file=rel_path)
            graph.add_edge(type_id, trait_id, EdgeType.IMPLEMENTS)

        # Extract methods inside impl body
        body = _find_child_by_type(node, "declaration_list")
        if body:
            for child in body.children:
                if child.type in lang_types.get("function_def", []):
                    func_id = self._extract_function(
                        child, source, lang, file_id, rel_path, graph
                    )
                    graph.add_edge(type_id, func_id, EdgeType.CONTAINS)
                    self._extract_calls_from(
                        child, source, lang, lang_types, func_id, rel_path, graph
                    )

    def _extract_fields(
        self,
        node: ts.Node,
        source: bytes,
        parent_id: str,
        graph: GraphData,
    ) -> None:
        """Extract fields from a struct/class body."""
        for child in node.children:
            if child.type in ("field_declaration", "field_declaration_list"):
                if child.type == "field_declaration_list":
                    for fc in child.children:
                        if fc.type == "field_declaration":
                            self._add_field_node(fc, source, parent_id, graph)
                else:
                    self._add_field_node(child, source, parent_id, graph)
            # Recurse into body
            if child.type in ("field_declaration_list", "struct_body", "class_body"):
                self._extract_fields(child, source, parent_id, graph)

    def _add_field_node(
        self,
        node: ts.Node,
        source: bytes,
        parent_id: str,
        graph: GraphData,
    ) -> None:
        """Add a Field node for a field declaration."""
        text = _node_text(node, source).strip().rstrip(";")
        # Use position as part of ID for uniqueness
        field_id = f"field:{parent_id}:{node.start_point[0]}:{node.start_point[1]}"
        graph.add_node(
            field_id,
            NodeLabel.FIELD,
            name=text[:200],
            type="",
        )
        graph.add_edge(parent_id, field_id, EdgeType.CONTAINS)

    def _extract_parameters(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        func_id: str,
        graph: GraphData,
    ) -> None:
        """Extract parameter nodes from a function definition."""
        param_list = _find_child_by_field(node, "parameters") or _find_child_by_type(
            node, "parameter_list", "formal_parameters", "parameters"
        )
        if not param_list:
            return

        idx = 0
        for child in param_list.children:
            if child.type in (
                "parameter_declaration",
                "parameter",
                "formal_parameter",
                "simple_parameter",
                "required_parameter",
                "optional_parameter",
            ):
                text = _node_text(child, source).strip()
                param_id = f"param:{func_id}:{idx}"
                graph.add_node(
                    param_id,
                    NodeLabel.PARAMETER,
                    name=text[:200],
                    index=idx,
                    function=func_id,
                )
                graph.add_edge(func_id, param_id, EdgeType.CONTAINS)
                idx += 1

    def _extract_calls_from(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        lang_types: dict[str, list[str]],
        caller_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Walk a subtree and extract CALLS edges."""
        call_types = lang_types.get("call", [])
        self._find_calls_recursive(node, source, call_types, caller_id, rel_path, graph)

    def _find_calls_recursive(
        self,
        node: ts.Node,
        source: bytes,
        call_types: list[str],
        caller_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Recursively find call expressions."""
        if node.type in call_types:
            callee_name, qualifier = self._get_callee_name(node, source)
            if callee_name:
                # Build funcref ID with qualifier if present
                if qualifier:
                    callee_id = f"funcref:{qualifier}.{callee_name}"
                else:
                    callee_id = f"funcref:{callee_name}"
                graph.add_node(callee_id, NodeLabel.FUNCTION, name=callee_name)
                if qualifier:
                    graph.add_edge(
                        caller_id, callee_id, EdgeType.CALLS, qualifier=qualifier,
                    )
                else:
                    graph.add_edge(caller_id, callee_id, EdgeType.CALLS)

        for child in node.children:
            self._find_calls_recursive(
                child, source, call_types, caller_id, rel_path, graph,
            )

    def _extract_inheritance(
        self,
        node: ts.Node,
        source: bytes,
        lang: str,
        cls_id: str,
        rel_path: str,
        graph: GraphData,
    ) -> None:
        """Extract INHERITS and IMPLEMENTS edges from class definitions."""
        # Look for base class / superclass specifiers
        for child in node.children:
            if child.type in (
                "base_class_clause",      # C++
                "superclass",             # Java, Kotlin, Swift
                "super_interfaces",       # Java
                "extends_type",           # TypeScript
                "class_heritage",         # JS/TS
                "superclass_clause",      # Swift
            ):
                base_text = _node_text(child, source).strip()
                # Simple heuristic: take the main type name
                for token in base_text.replace(",", " ").split():
                    token = token.strip(":{}() ")
                    if token and token not in ("extends", "implements", "public", "private",
                                                "protected", "virtual", ":"):
                        base_id = f"class:{rel_path}:{token}"
                        graph.add_edge(cls_id, base_id, EdgeType.INHERITS)

    # ── Name extraction helpers ─────────────────────────────────────────────

    def _get_function_name(self, node: ts.Node, source: bytes, lang: str) -> str:
        """Extract function name from a function definition node."""
        # Try field name first (most grammars use 'name' or 'declarator')
        name_node = _find_child_by_field(node, "name")
        if name_node:
            return _node_text(name_node, source)

        declarator = _find_child_by_field(node, "declarator")
        if declarator:
            # C/C++ — declarator can be nested (pointer_declarator, function_declarator)
            return self._unwrap_declarator(declarator, source)

        # Fallback: first identifier child
        for child in node.children:
            if child.type == "identifier":
                return _node_text(child, source)

        return f"anonymous_{node.start_point[0]}"

    def _unwrap_declarator(self, node: ts.Node, source: bytes) -> str:
        """Unwrap C/C++ declarators to find the actual name."""
        if node.type == "identifier":
            return _node_text(node, source)
        if node.type == "field_identifier":
            return _node_text(node, source)
        # function_declarator -> declarator -> identifier
        inner = _find_child_by_field(node, "declarator")
        if inner:
            return self._unwrap_declarator(inner, source)
        # Try first identifier
        for child in node.children:
            if child.type in ("identifier", "field_identifier"):
                return _node_text(child, source)
        return _node_text(node, source).split("(")[0].strip().split()[-1] if node.children else ""

    def _get_name(self, node: ts.Node, source: bytes, lang: str) -> str:
        """Generic name extraction for classes, structs, enums, etc."""
        name_node = _find_child_by_field(node, "name")
        if name_node:
            return _node_text(name_node, source)
        # Try first identifier
        for child in node.children:
            if child.type in ("identifier", "type_identifier", "name"):
                return _node_text(child, source)
        return f"anonymous_{node.start_point[0]}"

    def _get_macro_name(self, node: ts.Node, source: bytes) -> str:
        """Extract macro name from a preprocessor definition."""
        name_node = _find_child_by_field(node, "name")
        if name_node:
            return _node_text(name_node, source)
        # Second child is typically the name (after #define)
        for child in node.children:
            if child.type == "identifier":
                return _node_text(child, source)
        return f"macro_{node.start_point[0]}"

    def _get_function_params(self, node: ts.Node, source: bytes, lang: str) -> str:
        """Extract parameter string."""
        param_list = _find_child_by_field(node, "parameters") or _find_child_by_type(
            node, "parameter_list", "formal_parameters", "parameters"
        )
        if param_list:
            return _node_text(param_list, source)
        return ""

    def _get_function_return_type(self, node: ts.Node, source: bytes, lang: str) -> str:
        """Extract return type if available."""
        ret = _find_child_by_field(node, "return_type")
        if ret:
            return _node_text(ret, source)
        # C/C++: type is in the type specifier before the declarator
        type_node = _find_child_by_field(node, "type")
        if type_node:
            return _node_text(type_node, source)
        return ""

    _SKIP_QUALIFIERS = frozenset({"self", "this", "super", "Self"})

    def _get_callee_name(self, node: ts.Node, source: bytes) -> tuple[str, str | None]:
        """Extract the function being called and its qualifier.

        Returns (name, qualifier). qualifier is None when there is no receiver
        or when the receiver is self/this/super.
        """
        func_node = _find_child_by_field(node, "function")
        if func_node:
            text = _node_text(func_node, source)
            # Check for qualified call: obj.method, obj->method, ns::func
            for sep in ("->", "::", "."):
                if sep in text:
                    parts = text.rsplit(sep, 1)
                    qualifier = parts[0].strip()
                    name = parts[1].strip()
                    if qualifier in self._SKIP_QUALIFIERS:
                        return name, None
                    return name, qualifier
            return text.strip(), None

        # method_invocation (Java) — name field + optional object
        name_node = _find_child_by_field(node, "name")
        if name_node:
            name = _node_text(name_node, source)
            obj_node = _find_child_by_field(node, "object")
            if obj_node:
                qualifier = _node_text(obj_node, source)
                if qualifier in self._SKIP_QUALIFIERS:
                    return name, None
                return name, qualifier
            return name, None

        # message_expression (ObjC)
        selector = _find_child_by_field(node, "selector")
        if selector:
            return _node_text(selector, source), None

        return "", None

    def _parse_import_target(self, text: str) -> str:
        """Parse import/include text to extract the module name."""
        text = text.strip()
        # C/C++: #include "file.h" or #include <file.h>
        if text.startswith("#include"):
            text = text[len("#include"):].strip()
            return text.strip('"<>').strip()
        # Rust: use foo::bar;
        if text.startswith("use "):
            return text[4:].rstrip(";").strip()
        # Java/Kotlin: import foo.bar.Baz;
        if text.startswith("import "):
            target = text[7:].rstrip(";").strip()
            # Remove "static " prefix
            if target.startswith("static "):
                target = target[7:]
            return target
        # JS/TS: import { x } from "module" or import "module"
        if "from" in text:
            parts = text.split("from")
            return parts[-1].strip().strip("'\"; ")
        if text.startswith("import "):
            return text[7:].strip("'\"(); ")
        return text[:200]

    def _is_exported(self, text: str, lang: str) -> bool:
        """Check if a function/symbol is exported."""
        first_line = text.split("\n")[0] if "\n" in text else text
        if lang in ("c", "cpp"):
            return "static" not in first_line
        if lang == "rust":
            return first_line.strip().startswith("pub ")
        if lang in ("java", "kotlin"):
            return "public" in first_line
        if lang == "go":
            # Go exports start with uppercase
            parts = first_line.split("func")
            if len(parts) > 1:
                name_part = parts[1].strip().lstrip("(")
                return name_part[:1].isupper() if name_part else False
        if lang == "swift":
            return "private" not in first_line and "fileprivate" not in first_line
        if lang in ("javascript", "typescript"):
            return "export" in first_line
        return True
