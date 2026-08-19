# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Code indexer: deterministic code index for deep scan.

Builds a structural index of the target codebase using tree-sitter:
- Function/method inventory with location and body (FR-020)
- Call graph: which function calls which (FR-021)
- Query interface: get-function-body, get-callers, get-callees, find-symbol (FR-022)
- Incremental on re-run: only changed files re-parsed (FR-026)

The Indexer uses a deterministic parser (tree-sitter) as required by FR-020.
LLM extraction is NOT used for indexing — the parser is the sole source.

Constitution alignment:
  XI. Persist Atomically — index writes are atomic via temp-then-rename
"""

import hashlib
import json
import logging
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from tree_sitter import Language, Parser

logger = logging.getLogger(__name__)

# --- Language registry ---

# Map file extensions to tree-sitter language modules
_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sc": "scala",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "c_sharp",
    ".php": "php",
    ".swift": "swift",
    ".sh": "bash",
    ".bash": "bash",
}

# Tree-sitter node types that represent function definitions per language
_FUNCTION_NODE_TYPES: Dict[str, Set[str]] = {
    "python": {"function_definition", "decorated_definition"},
    "java": {"method_declaration", "constructor_declaration"},
    "javascript": {"function_declaration", "generator_function_declaration",
                   "method_definition", "arrow_function", "function_expression",
                   "function"},
    "typescript": {"function_declaration", "generator_function_declaration",
                   "method_definition", "arrow_function", "function_expression",
                   "function"},
    "tsx": {"function_declaration", "generator_function_declaration",
            "method_definition", "arrow_function", "function_expression",
            "function"},
    "go": {"function_declaration", "method_declaration"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "ruby": {"method", "singleton_method"},
    "rust": {"function_item"},
    "scala": {"function_definition", "class_definition", "object_definition"},
    "kotlin": {"function_declaration"},
    "c_sharp": {"method_declaration", "constructor_declaration"},
    "php": {"function_definition", "method_declaration"},
    "swift": {"function_declaration"},
    "bash": {"function_definition"},
}

# Node types that represent function/method calls
_CALL_NODE_TYPES: Dict[str, Set[str]] = {
    "python": {"call"},
    "java": {"method_invocation"},
    "javascript": {"call_expression"},
    "typescript": {"call_expression"},
    "tsx": {"call_expression"},
    "go": {"call_expression"},
    "c": {"call_expression"},
    "cpp": {"call_expression"},
    "ruby": {"method_call", "call"},
    "rust": {"call_expression"},
    "scala": {"call_expression"},
    "kotlin": {"call_expression"},
    "c_sharp": {"invocation_expression"},
    "php": {"function_call_expression"},
    "swift": {"call_expression"},
    "bash": {"command"},
}


# Languages where a declaration may carry no body at all: interface members,
# abstract and partial declarations, extern methods.  Such a declaration is a
# signature with nothing to analyse, so indexing it only spends an LLM call.
# Add a language here only after checking that its grammar exposes the body
# under the "body" field, otherwise every function in it would be skipped.
_BODYLESS_DECLARATION_LANGUAGES: Set[str] = {"c_sharp", "java"}


# Statements that sit directly under the file root instead of inside a function.
# C# top-level statements (.NET 6+) compile into an implicit Main, and that is
# where modern ASP.NET wires up authentication, CORS and endpoints - code that
# would otherwise belong to no function and never be analysed.
_TOP_LEVEL_STATEMENT_TYPES: Dict[str, Set[str]] = {
    "c_sharp": {"global_statement"},
}

# Name given to the synthetic function built from a file's top-level statements.
_TOP_LEVEL_NAME = "<top-level>"


# Languages whose pip module or loader function is not named after the language.
# TSX needs its own grammar: the plain TypeScript one cannot parse JSX syntax.
_GRAMMAR_SPECS: Dict[str, Tuple[str, str]] = {
    "tsx": ("typescript", "language_tsx"),
}


# Function nodes that carry no name of their own: the name, if any, comes from
# whatever binds them.  Dominant in modern JS/TS — `const Foo = () => {}`.
_ANONYMOUS_FUNCTION_TYPES: Set[str] = {"arrow_function", "function_expression", "function"}

# Binding node type -> field holding the name it gives to the function.
_NAME_BINDING_FIELDS: Dict[str, str] = {
    "variable_declarator": "name",        # const Foo = () => {}
    "assignment_expression": "left",      # obj.handler = () => {}
    "public_field_definition": "name",    # class C { handle = () => {} }
    "field_definition": "name",
    "pair": "key",                        # { onSave: () => {} }
}

# Nodes that may sit between a function and its binding without hiding it:
# useCallback(fn), useMemo(fn), React.memo(fn), forwardRef(fn), (fn), fn as T.
_TRANSPARENT_PARENT_TYPES: Set[str] = {
    "arguments", "call_expression", "parenthesized_expression",
    "await_expression", "as_expression", "satisfies_expression",
    "type_assertion", "non_null_expression",
}

# Node types accepted as a derived function name (rejects array/object patterns,
# so `const [a, setA] = useState(() => ...)` does not produce a bogus name).
_NAME_NODE_TYPES: Set[str] = {
    "identifier", "property_identifier", "shorthand_property_identifier",
    "private_property_identifier",
}

# How many parents to walk while looking for a binding.
_MAX_BINDING_DEPTH = 5


def _load_language(lang_name: str) -> Optional[Language]:
    """Load a tree-sitter language by name."""
    module_name, loader_name = _GRAMMAR_SPECS.get(lang_name, (lang_name, ""))
    try:
        module = __import__(f"tree_sitter_{module_name}")
        if loader_name:
            loader = getattr(module, loader_name)
        else:
            # PHP uses language_php() instead of language()
            loader = getattr(module, f"language_{lang_name}", None) or getattr(module, "language")
        return Language(loader())
    except (ImportError, AttributeError) as e:
        logger.debug("Language %s not available: %s", lang_name, e)
        return None


def _get_language_for_file(file_path: str) -> Optional[str]:
    """Get the language name for a file based on extension."""
    ext = os.path.splitext(file_path)[1].lower()
    return _LANGUAGE_MAP.get(ext)


# A file with no functions is worth analysing when it configures something. The
# signal list is deliberately broad: a false positive costs one LLM call, a false
# negative is a blind spot in auth or configuration analysis.
_CONFIG_SIGNALS = (
    re.compile(r"import\.meta\.env|process\.env"),
    re.compile(r"https?://"),
    re.compile(r"export\s+(default\s+)?(const|var|let)\s+\w+\s*(:[^=]+)?=\s*\{"),
    re.compile(r"localStorage|sessionStorage|document\.cookie"),
    re.compile(r"(?i)\b(token|secret|apikey|api_key|credential|password)\b"),
    re.compile(r"(?i)(auth|oidc|keycloak|oauth|jwt|login|permission|role)"),
    re.compile(r"window\.(location|history|open)|document\.(write|getElementById)"),
    re.compile(r"defineConfig|createRoot|configureStore|new\s+[A-Z]\w*Client\s*\("),
)

# Comments, matched over the whole text so a block comment spanning several
# lines is removed in one piece rather than confusing a line-oriented check.
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)

# Import and re-export statements, matched over the whole text rather than
# line by line: Prettier's default formatting wraps a grouped export across
# several lines (`export {\n    Foo,\n    Bar,\n} from './x';`), and a
# per-line check never recognises the interior lines as anything, so it
# never confirms the file is barrel-only. Matching the statement as one
# unit - non-greedy up to its terminating semicolon - handles it regardless
# of how many lines it spans.
_IMPORT_OR_REEXPORT = re.compile(
    r"import\s[\s\S]*?;"
    r"|export\s+\*\s*(as\s+\w+\s+)?from\s+['\"][^'\"]+['\"]\s*;?"
    r"|export\s*\{[\s\S]*?\}\s*(from\s+['\"][^'\"]+['\"])?\s*;?"
)

# Whole-file units are sent to the LLM in one prompt; past this they crowd out
# the answer, so they are reported as skipped rather than silently truncated.
MAX_WHOLE_FILE_CHARS = 20000


def _is_barrel_reexport(source: str) -> bool:
    """True when a file contains nothing but imports and re-exports.

    Strips comments and every recognised import/export statement from the
    whole text and checks what is left is blank. Whole-text rather than
    line-by-line so multi-line grouped exports are recognised as a single
    statement instead of defeating the check on their interior lines.
    """
    remainder = _COMMENT.sub("", source)
    remainder = _IMPORT_OR_REEXPORT.sub("", remainder)
    return remainder.strip() == ""


def _is_analysable_config(source: str) -> bool:
    """True when a function-less file configures something worth analysing."""
    if _is_barrel_reexport(source):
        return False
    return any(rx.search(source) for rx in _CONFIG_SIGNALS)


# --- Data classes ---

class FunctionInfo:
    """Information about a function/method in the codebase."""

    def __init__(self, name: str, file_path: str, start_line: int, end_line: int,
                 body: str, language: str, class_name: Optional[str] = None):
        self.name = name
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.body = body
        self.language = language
        self.class_name = class_name

    @property
    def qualified_name(self) -> str:
        if self.class_name:
            return f"{self.class_name}.{self.name}"
        return self.name

    @property
    def key(self) -> str:
        # start_line disambiguates same-named functions in one file: React files
        # routinely define many callbacks called renderCell, and without it each
        # overwrites the previous one in the index dict.
        return f"{self.file_path}:{self.qualified_name}:{self.start_line}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "qualified_name": self.qualified_name,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "body": self.body,
            "language": self.language,
            "class_name": self.class_name,
        }


# --- Parser ---

class TreeSitterParser:
    """Tree-sitter based parser for extracting functions and call sites."""

    def __init__(self):
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, Language] = {}
        # Files tree-sitter could only parse partially (FR-028): without this the
        # index silently under-reports, e.g. JSX parsed by a non-JSX grammar.
        self.syntax_error_files: List[str] = []

    def reset_diagnostics(self) -> None:
        """Forget syntax errors recorded by earlier parse_file calls."""
        self.syntax_error_files = []

    def _get_parser(self, lang_name: str) -> Optional[Parser]:
        """Get or create a parser for the given language."""
        if lang_name not in self._parsers:
            language = _load_language(lang_name)
            if language is None:
                return None
            parser = Parser(language)
            self._parsers[lang_name] = parser
            self._languages[lang_name] = language
        return self._parsers.get(lang_name)

    def parse_file(self, file_path: str, source: Optional[bytes] = None) -> Tuple[List[FunctionInfo], List[Tuple[str, str]]]:
        """
        Parse a file and extract functions and call relationships.

        Returns:
            (functions, calls) where calls is a list of (caller_key, callee_name) tuples
        """
        lang_name = _get_language_for_file(file_path)
        if not lang_name:
            return [], []

        parser = self._get_parser(lang_name)
        if not parser:
            return [], []

        if source is None:
            try:
                with open(file_path, "rb") as f:
                    source = f.read()
            except (OSError, IOError) as e:
                logger.warning("Cannot read %s: %s", file_path, e)
                return [], []

        tree = parser.parse(source)
        if tree.root_node.has_error:
            self._record_syntax_error(file_path, tree.root_node, lang_name)
        functions = self._extract_functions(tree.root_node, file_path, source, lang_name)
        calls = self._extract_calls(tree.root_node, file_path, source, lang_name, functions)
        return functions, calls

    def _record_syntax_error(self, file_path: str, root_node, lang_name: str) -> None:
        """Log a partial parse and remember the file (FR-028)."""
        self.syntax_error_files.append(file_path)
        first_error = self._first_error_node(root_node)
        where = f" near line {first_error.start_point[0] + 1}" if first_error else ""
        logger.warning("Partial parse of %s (%s grammar)%s - some functions may be missing",
                       file_path, lang_name, where)

    @staticmethod
    def _first_error_node(root_node, max_nodes: int = 5000):
        """Find the first error/missing node, bounded so huge trees stay cheap."""
        stack = [root_node]
        visited = 0
        while stack and visited < max_nodes:
            node = stack.pop()
            visited += 1
            if node.is_error or node.is_missing:
                return node
            if node.has_error:
                stack.extend(reversed(node.children))
        return None

    def _extract_functions(self, root_node, file_path: str, source: bytes,
                           lang_name: str) -> List[FunctionInfo]:
        """Extract all function/method definitions from the parse tree."""
        functions: List[FunctionInfo] = []
        func_types = _FUNCTION_NODE_TYPES.get(lang_name, set())

        def visit(node, class_name=None, enclosing_func=None):
            # Track class context
            current_class = class_name
            if node.type in ("class_definition", "class_declaration",
                             "class_body", "interface_declaration"):
                name_node = node.child_by_field_name("name")
                if name_node:
                    current_class = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")

            current_func = enclosing_func
            if node.type in func_types:
                func_info = self._node_to_function(node, file_path, source, lang_name,
                                                   current_class, enclosing_func)
                if func_info:
                    functions.append(func_info)
                    current_func = func_info.name

            # Handle Python decorated_definition: the function is inside it
            if node.type == "decorated_definition" and lang_name == "python":
                for child in node.children:
                    if child.type == "function_definition":
                        func_info = self._node_to_function(child, file_path, source, lang_name, current_class)
                        if func_info:
                            functions.append(func_info)
                return  # Don't recurse into decorated_definition children again

            for child in node.children:
                visit(child, current_class, current_func)

        visit(root_node)

        top_level = self._top_level_function(root_node, file_path, source, lang_name)
        if top_level:
            functions.append(top_level)

        return functions

    @staticmethod
    def _top_level_function(root_node, file_path: str, source: bytes,
                            lang_name: str) -> Optional[FunctionInfo]:
        """
        Build one synthetic function from a file's top-level statements.

        Returns None for languages without them, and for files that declare a
        real entry point instead, so nothing is indexed twice.
        """
        statement_types = _TOP_LEVEL_STATEMENT_TYPES.get(lang_name)
        if not statement_types:
            return None

        statements = [c for c in root_node.children if c.type in statement_types]
        if not statements:
            return None

        first, last = statements[0], statements[-1]
        return FunctionInfo(
            name=_TOP_LEVEL_NAME,
            file_path=file_path,
            start_line=first.start_point[0] + 1,
            end_line=last.end_point[0] + 1,
            body=source[first.start_byte:last.end_byte].decode("utf-8", errors="replace"),
            language=lang_name,
            class_name=None,
        )

    def _node_to_function(self, node, file_path: str, source: bytes,
                          lang_name: str, class_name: Optional[str],
                          enclosing_func: Optional[str] = None) -> Optional[FunctionInfo]:
        """Convert a tree-sitter node to FunctionInfo."""
        if (lang_name in _BODYLESS_DECLARATION_LANGUAGES
                and node.child_by_field_name("body") is None):
            return None

        name_node = node.child_by_field_name("name")
        container = class_name

        if name_node:
            name = source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        elif node.type in _ANONYMOUS_FUNCTION_TYPES:
            name = self._derive_bound_name(node, source)
            if not name:
                # Inline callback (onClick={() => ...}, arr.map(x => ...)): it is
                # already part of its parent's body, so indexing it adds only noise.
                return None
            # Qualify by whatever contains it, so two components in one file can
            # both declare handleSubmit without colliding on the index key.
            container = class_name or enclosing_func
        else:
            return None

        body = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1

        return FunctionInfo(
            name=name,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            body=body,
            language=lang_name,
            class_name=container,
        )

    @staticmethod
    def _derive_bound_name(node, source: bytes) -> Optional[str]:
        """
        Name an anonymous function from what binds it.

        Handles the shapes React code is written in: `const Foo = () => {}`,
        `const handle = useCallback(() => {}, [])`, `export default memo(() => {})`,
        `obj.onSave = function () {}`.  Returns None when nothing binds it.
        """
        parent = node.parent
        for _ in range(_MAX_BINDING_DEPTH):
            if parent is None:
                return None

            field = _NAME_BINDING_FIELDS.get(parent.type)
            if field:
                target = parent.child_by_field_name(field)
                if target is None:
                    return None
                text = source[target.start_byte:target.end_byte].decode("utf-8", errors="replace")
                if target.type in _NAME_NODE_TYPES:
                    return text
                if target.type == "member_expression":
                    return text.rsplit(".", 1)[-1]
                return None  # destructuring pattern, computed key, ...

            if parent.type not in _TRANSPARENT_PARENT_TYPES:
                return None
            parent = parent.parent

        return None

    def _extract_calls(self, root_node, file_path: str, source: bytes,
                       lang_name: str, functions: List[FunctionInfo]) -> List[Tuple[str, str]]:
        """Extract call relationships: which function calls which."""
        call_types = _CALL_NODE_TYPES.get(lang_name, set())
        calls: List[Tuple[str, str]] = []

        # Build a line-range to function-key map
        func_ranges: List[Tuple[int, int, str]] = []
        for func in functions:
            func_ranges.append((func.start_line, func.end_line, func.key))

        def find_containing_function(line: int) -> Optional[str]:
            for start, end, key in func_ranges:
                if start <= line <= end:
                    return key
            return None

        def visit(node):
            if node.type in call_types:
                callee_name = self._extract_callee_name(node, source, lang_name)
                if callee_name:
                    call_line = node.start_point[0] + 1
                    caller_key = find_containing_function(call_line)
                    if caller_key:
                        calls.append((caller_key, callee_name))

            for child in node.children:
                visit(child)

        visit(root_node)
        return calls

    def _extract_callee_name(self, call_node, source: bytes, lang_name: str) -> Optional[str]:
        """Extract the name being called from a call expression node."""
        if lang_name == "python":
            func_node = call_node.child_by_field_name("function")
            if func_node:
                # Handle obj.method() — extract just the method name
                if func_node.type == "attribute":
                    attr = func_node.child_by_field_name("attribute")
                    if attr:
                        return source[attr.start_byte:attr.end_byte].decode("utf-8", errors="replace")
                return source[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")
        elif lang_name == "java":
            name_node = call_node.child_by_field_name("name")
            if name_node:
                return source[name_node.start_byte:name_node.end_byte].decode("utf-8", errors="replace")
        else:
            # Generic: try 'function' field first, then 'name'
            for field in ("function", "name"):
                child = call_node.child_by_field_name(field)
                if child:
                    if child.type in ("member_expression", "attribute", "field_expression"):
                        prop = child.child_by_field_name("property") or child.child_by_field_name("attribute") or child.child_by_field_name("field")
                        if prop:
                            return source[prop.start_byte:prop.end_byte].decode("utf-8", errors="replace")
                    return source[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
        return None


# --- Code Index ---

# Bodies at or below this many non-blank lines are callbacks and predicates
# (`x => x.id`), not analysable units. Overridable via --min-function-lines.
DEFAULT_MIN_FUNCTION_LINES = 4


def _body_line_count(body: str) -> int:
    """Non-blank lines in a function body."""
    return len([line for line in (body or "").splitlines() if line.strip()])


class CodeIndex:
    """
    Queryable code index implementing FR-022.

    Provides: get_function_body, get_callers, get_callees,
    find_symbol, full_text_search, list_functions_in_file.
    """

    def __init__(self, min_function_lines: int = DEFAULT_MIN_FUNCTION_LINES):
        self._functions: Dict[str, FunctionInfo] = {}  # key → FunctionInfo
        self._by_name: Dict[str, List[str]] = defaultdict(list)  # name → [keys]
        self._by_file: Dict[str, List[str]] = defaultdict(list)  # file → [keys]
        self._callees: Dict[str, Set[str]] = defaultdict(set)  # caller_key → {callee_names}
        self._callers: Dict[str, Set[str]] = defaultdict(set)  # callee_name → {caller_keys}
        self._file_hashes: Dict[str, str] = {}  # file_path → content hash
        self._parser = TreeSitterParser()
        self._queryable = False
        self.min_function_lines = min_function_lines

    @property
    def is_queryable(self) -> bool:
        """Whether the index has been built and is ready for queries (FR-024)."""
        return self._queryable

    def build(self, target_path: str, include_patterns: Optional[List[str]] = None,
              exclude_patterns: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Build the index from a target directory or file (FR-020, FR-021).

        Respects configured scope via include/exclude patterns (FR-027).
        Degrades gracefully on unparseable files (FR-028).
        """
        stats = {"files_parsed": 0, "files_skipped": 0, "functions_found": 0,
                 "calls_found": 0, "errors": 0, "files_with_syntax_errors": 0,
                 "functions_skipped_trivial": 0, "whole_file_units": 0}
        self._parser.reset_diagnostics()

        if os.path.isfile(target_path):
            files = [target_path]
        else:
            files = self._collect_files(target_path, include_patterns, exclude_patterns)

        for file_path in files:
            try:
                content_hash = self._hash_file(file_path)

                # Incremental: skip unchanged files (FR-026)
                if file_path in self._file_hashes and self._file_hashes[file_path] == content_hash:
                    stats["files_skipped"] += 1
                    continue

                functions, calls = self._parser.parse_file(file_path)

                if not functions and _get_language_for_file(file_path):
                    unit = self._whole_file_unit(file_path)
                    if unit is None:
                        stats["files_skipped"] += 1
                        continue
                    self._remove_file(file_path)
                    self._functions[unit.key] = unit
                    self._by_name[unit.name].append(unit.key)
                    self._by_file[file_path].append(unit.key)
                    self._file_hashes[file_path] = content_hash
                    stats["files_parsed"] += 1
                    stats["whole_file_units"] += 1
                    stats["functions_found"] = len(self._functions)
                    continue

                # Remove old entries for this file before adding new ones
                self._remove_file(file_path)

                for func in functions:
                    if _body_line_count(func.body) < self.min_function_lines:
                        stats["functions_skipped_trivial"] += 1
                        continue
                    self._functions[func.key] = func
                    self._by_name[func.name].append(func.key)
                    self._by_file[file_path].append(func.key)

                for caller_key, callee_name in calls:
                    self._callees[caller_key].add(callee_name)
                    self._callers[callee_name].add(caller_key)

                self._file_hashes[file_path] = content_hash
                stats["files_parsed"] += 1
                stats["calls_found"] += len(calls)

            except Exception as e:
                logger.warning("Failed to parse %s: %s", file_path, e)
                stats["errors"] += 1

        stats["files_with_syntax_errors"] = len(self._parser.syntax_error_files)
        if stats["files_with_syntax_errors"]:
            logger.warning("%d file(s) parsed only partially - coverage is incomplete",
                           stats["files_with_syntax_errors"])

        stats["functions_found"] = len(self._functions)
        self._queryable = stats["functions_found"] > 0 or len(self._functions) > 0
        logger.info("Index built: %d files, %d functions, %d calls (%d trivial skipped)",
                     stats["files_parsed"], stats["functions_found"],
                     stats["calls_found"], stats["functions_skipped_trivial"])
        return stats

    def _whole_file_unit(self, file_path: str) -> Optional[FunctionInfo]:
        """A function-less config file as a single analysable unit, or None."""
        try:
            with open(file_path, encoding="utf-8", errors="replace") as handle:
                source = handle.read()
        except OSError as e:
            logger.warning("Cannot read %s for config analysis: %s", file_path, e)
            return None

        if len(source) > MAX_WHOLE_FILE_CHARS:
            logger.warning("Config file %s is %d chars (limit %d) - not analysed",
                           file_path, len(source), MAX_WHOLE_FILE_CHARS)
            return None

        if not _is_analysable_config(source):
            return None

        return FunctionInfo(
            name="(file)", file_path=file_path, start_line=1,
            end_line=len(source.splitlines()) or 1, body=source,
            language=_get_language_for_file(file_path) or "",
        )

    def _remove_file(self, file_path: str):
        """Remove all entries for a file (for re-indexing)."""
        old_keys = self._by_file.pop(file_path, [])
        for key in old_keys:
            func = self._functions.pop(key, None)
            # Clean up name index: read the name off the FunctionInfo we just
            # removed, not by parsing the key, since the key's segment count
            # is an implementation detail that has changed before.
            if func is not None and func.name in self._by_name:
                self._by_name[func.name] = [k for k in self._by_name[func.name] if k != key]
            # Clean up call graph
            self._callees.pop(key, None)
            for callee, callers in self._callers.items():
                callers.discard(key)

    def _collect_files(self, directory: str,
                       include_patterns: Optional[List[str]],
                       exclude_patterns: Optional[List[str]]) -> List[str]:
        """Collect files to index, respecting scope rules (FR-027)."""
        files: List[str] = []
        exclude = set(exclude_patterns or [])
        # Default excludes
        default_excludes = {".git", "node_modules", "__pycache__", ".venv", "venv",
                           "vendor", "target", "build", "dist", ".tox", ".eggs"}
        exclude.update(default_excludes)

        for root, dirs, filenames in os.walk(directory):
            # Filter directories
            dirs[:] = [d for d in dirs if d not in exclude
                       and not any(d.startswith(p) for p in exclude if not p.startswith("."))]

            for filename in filenames:
                file_path = os.path.join(root, filename)
                lang = _get_language_for_file(file_path)
                if lang is None:
                    continue

                if include_patterns:
                    if not any(file_path.endswith(p.lstrip("*")) for p in include_patterns):
                        continue

                files.append(file_path)

        return sorted(files)

    @staticmethod
    def _hash_file(file_path: str) -> str:
        """Compute content hash for incremental indexing."""
        h = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    # --- Query interface (FR-022) ---

    def get_function_body(self, file_path: str, function_name: str) -> Optional[str]:
        """Get the body of a specific function."""
        for key in self._by_file.get(file_path, []):
            func = self._functions.get(key)
            if func and function_name in (func.name, func.qualified_name):
                return func.body
        return None

    def get_callers(self, function_name: str) -> List[Dict[str, Any]]:
        """Get all functions that call the given function (FR-021)."""
        caller_keys = self._callers.get(function_name, set())
        result = []
        for key in caller_keys:
            func = self._functions.get(key)
            if func:
                result.append(func.to_dict())
        return result

    def get_callees(self, file_path: str, function_name: str) -> List[str]:
        """Get all functions called by the given function (FR-021)."""
        for key in self._by_file.get(file_path, []):
            func = self._functions.get(key)
            if func and function_name in (func.name, func.qualified_name):
                return sorted(self._callees.get(key, set()))
        return []

    def find_symbol(self, name: str) -> List[Dict[str, Any]]:
        """Find all functions/methods with the given name (FR-022)."""
        keys = self._by_name.get(name, [])
        return [self._functions[k].to_dict() for k in keys if k in self._functions]

    def list_functions_in_file(self, file_path: str) -> List[Dict[str, Any]]:
        """List all functions defined in a file (FR-020)."""
        keys = self._by_file.get(file_path, [])
        return [self._functions[k].to_dict() for k in keys if k in self._functions]

    def full_text_search(self, query: str, case_sensitive: bool = False) -> List[Dict[str, Any]]:
        """Search function bodies for a text pattern (FR-022)."""
        results = []
        if not case_sensitive:
            query = query.lower()
        for func in self._functions.values():
            body = func.body if case_sensitive else func.body.lower()
            if query in body:
                results.append(func.to_dict())
        return results

    def get_all_functions(self) -> List[Dict[str, Any]]:
        """Get all indexed functions."""
        return [f.to_dict() for f in self._functions.values()]

    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics."""
        languages: Dict[str, int] = defaultdict(int)
        for func in self._functions.values():
            languages[func.language] += 1

        return {
            "total_functions": len(self._functions),
            "total_files": len(self._by_file),
            "total_call_edges": sum(len(v) for v in self._callees.values()),
            "languages": dict(languages),
            "queryable": self._queryable,
        }

    # --- Persistence ---

    def save(self, path: str):
        """
        Save the index to a JSON file (FR-025).

        Uses write-to-temp-then-rename for atomic persistence (Constitution XI).
        """
        data = {
            "functions": {k: v.to_dict() for k, v in self._functions.items()},
            "callees": {k: sorted(v) for k, v in self._callees.items()},
            "callers": {k: sorted(v) for k, v in self._callers.items()},
            "file_hashes": self._file_hashes,
        }
        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
        logger.info("Index saved to %s", path)

    def load(self, path: str) -> bool:
        """Load a previously saved index."""
        if not os.path.exists(path):
            return False
        try:
            with open(path, "r") as f:
                data = json.load(f)

            self._functions = {}
            for key, fdict in data.get("functions", {}).items():
                self._functions[key] = FunctionInfo(**{k: v for k, v in fdict.items()
                                                       if k != "qualified_name"})
                self._by_name[fdict["name"]].append(key)
                self._by_file[fdict["file_path"]].append(key)

            self._callees = {k: set(v) for k, v in data.get("callees", {}).items()}
            self._callers = {k: set(v) for k, v in data.get("callers", {}).items()}
            self._file_hashes = data.get("file_hashes", {})
            self._queryable = len(self._functions) > 0

            logger.info("Index loaded from %s: %d functions", path, len(self._functions))
            return True
        except (json.JSONDecodeError, OSError, TypeError) as e:
            logger.error("Failed to load index from %s: %s", path, e)
            return False
