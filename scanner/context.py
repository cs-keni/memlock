# Per-file analysis context: store file path, source code, AST, and helper methods.
# Handles reading/parsing C files, error handling for unreadable/malformed files,
# and logging of node/function counts so ASTs are ready for rules.

import logging
from pathlib import Path
from typing import Optional

from scanner.parser import create_parser, parse_bytes
from tree_sitter import Parser, Tree
from tree_sitter import Node as TSNode

logger = logging.getLogger(__name__)


def _count_nodes(node: TSNode) -> int:
    """Count all descendants of node (including node itself)."""
    count = 1
    for child in node.children:
        count += _count_nodes(child)
    return count


def _count_functions(root: TSNode) -> int:
    """Count function_definition nodes under root."""
    count = 0
    if root.type == "function_definition":
        count += 1
    for child in root.children:
        count += _count_functions(child)
    return count


def count_tree_stats(root: TSNode) -> tuple[int, int]:
    """
    Return (total node count, function definition count) for the tree.

    Useful for logging how much was parsed (nodes and functions).
    """
    return _count_nodes(root), _count_functions(root)


class FileContext:
    """
    Per-file state for static analysis: path, raw source bytes, and AST.

    Rules use context.path, context.source, and context.tree. Use
    get_source_span(context, node) and get_line_col(node) for locations/snippets.
    """

    def __init__(
        self,
        path: Path,
        source: bytes,
        tree: Tree,
        *,
        has_parse_errors: bool = False,
    ) -> None:
        self.path = path
        self.source = source
        self.tree = tree
        self.has_parse_errors = has_parse_errors

    @property
    def root_node(self) -> TSNode:
        """Convenience access to the AST root."""
        return self.tree.root_node


def get_source_span(context: FileContext, node: TSNode) -> str:
    """
    Return the substring of context.source for the given node's byte range.

    Decodes with errors="replace" so bad UTF-8 does not crash.
    """
    return context.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def get_line_col(node: TSNode, one_based: bool = True) -> tuple[int, int]:
    """
    Return (line, column) for the node's start position.

    Tree-sitter uses 0-based (row, col). If one_based=True (default),
    returns 1-based line and column for display/SARIF.
    """
    row, col = node.start_point
    if one_based:
        return row + 1, col + 1
    return row, col


def create_context(
    path: Path,
    parser: Optional[Parser] = None,
) -> Optional[FileContext]:
    """
    Read a C file and parse it into a FileContext (path, source, AST).

    - Unreadable file (permission, missing): returns None and logs error.
    - Malformed C (syntax errors): still returns a FileContext with the tree
      and sets has_parse_errors=True; logs a warning and node/function counts.
    - Success: returns FileContext and logs node count and function count.

    Returns:
        FileContext if the file was read (and parsed), None if the file
        could not be read.
    """
    if parser is None:
        parser = create_parser()

    try:
        source = path.read_bytes()
    except OSError as e:
        logger.error("Failed to read file %s: %s", path, e)
        return None

    tree = parse_bytes(source, parser=parser)
    has_errors = tree.root_node.has_error
    if has_errors:
        logger.warning("File %s parsed with syntax errors; AST may be incomplete", path)

    node_count, func_count = count_tree_stats(tree.root_node)
    logger.info(
        "Parsed %s: %d nodes, %d function(s)%s",
        path,
        node_count,
        func_count,
        " (with parse errors)" if has_errors else "",
    )

    return FileContext(
        path=path,
        source=source,
        tree=tree,
        has_parse_errors=has_errors,
    )


def load_contexts(
    paths: list[Path],
    parser: Optional[Parser] = None,
) -> list[FileContext]:
    """
    Read and parse multiple C files into FileContexts (ASTs in memory).

    Unreadable or missing files are skipped (logged); malformed files still
    get a context with has_parse_errors=True. Returns only successfully
    loaded contexts (each holds an AST in memory for analysis).

    Args:
        paths: List of paths to .c files (e.g. from traversal.find_c_files).
        parser: Optional shared parser; if None, one is created per file.

    Returns:
        List of FileContext instances, one per file that could be read.
        Order matches input order; failed files are omitted.
    """
    if parser is None:
        parser = create_parser()

    contexts: list[FileContext] = []
    for path in paths:
        ctx = create_context(path, parser=parser)
        if ctx is not None:
            contexts.append(ctx)
    return contexts
