# Tree-sitter setup and AST parsing: parse C source code into AST trees.

import logging
from pathlib import Path
from typing import Optional

import tree_sitter
from tree_sitter import Language
from tree_sitter_c import language as _c_language_capsule

logger = logging.getLogger(__name__)

# C language grammar: wrap tree-sitter-c capsule for use with tree_sitter.Parser
_C_LANGUAGE = Language(_c_language_capsule())


def get_c_language() -> Language:
    """Return the Tree-sitter Language object for C."""
    return _C_LANGUAGE


def create_parser() -> tree_sitter.Parser:
    """Create and return a Tree-sitter Parser configured for C."""
    parser = tree_sitter.Parser(_C_LANGUAGE)
    return parser


def parse_bytes(
    source: bytes,
    parser: Optional[tree_sitter.Parser] = None,
) -> tree_sitter.Tree:
    """
    Parse C source bytes into an AST.

    Args:
        source: UTF-8 encoded C source code.
        parser: Optional parser instance; if None, a new one is created.

    Returns:
        The parse tree. Check tree.root_node for errors (e.g. ERROR nodes).
    """
    if parser is None:
        parser = create_parser()
    tree = parser.parse(source)
    if tree.root_node.has_error:
        logger.warning(
            "Parse completed with errors: root=%s",
            tree.root_node.type,
        )
    else:
        logger.debug(
            "Parse succeeded: root=%s",
            tree.root_node.type,
        )
    return tree


def parse_file(path: Path, parser: Optional[tree_sitter.Parser] = None) -> Optional[tree_sitter.Tree]:
    """
    Parse a C source file into an AST.

    Args:
        path: Path to the .c file.
        parser: Optional parser instance; if None, a new one is created.

    Returns:
        The parse tree, or None if the file could not be read.
    """
    try:
        source = path.read_bytes()
    except OSError as e:
        logger.error("Failed to read file %s: %s", path, e)
        return None
    tree = parse_bytes(source, parser=parser)
    logger.info("Parsed file %s: success=%s", path, not tree.root_node.has_error)
    return tree
