"""Tests for tree-sitter C parser wrapper."""

import logging
from pathlib import Path


from scanner.parser import (
    create_parser,
    get_c_language,
    parse_bytes,
    parse_file,
)


def test_get_c_language_returns_language():
    """get_c_language() returns a tree-sitter Language object."""
    lang = get_c_language()
    assert lang is not None
    # tree_sitter.Language has no public type name; just ensure it's truthy
    assert lang


def test_create_parser_returns_parser():
    """create_parser() returns a configured Parser."""
    parser = create_parser()
    assert parser is not None
    assert parser.language is not None


def test_parse_bytes_success(caplog):
    """Parsing valid C source succeeds and logs."""
    source = b"int main(void) { return 0; }"
    parser = create_parser()
    with caplog.at_level(logging.DEBUG):
        tree = parse_bytes(source, parser=parser)
    assert tree is not None
    assert tree.root_node is not None
    assert not tree.root_node.has_error
    assert tree.root_node.type == "translation_unit"
    # Logging: either debug (success) or warning (errors)
    assert "Parse" in caplog.text or "parse" in caplog.text.lower()


def test_parse_bytes_invalid_c_logs_failure(caplog):
    """Parsing invalid C logs parse failure (has_error)."""
    source = b"int main( { broken"
    parser = create_parser()
    with caplog.at_level(logging.WARNING):
        tree = parse_bytes(source, parser=parser)
    assert tree is not None
    # Parser may still produce a tree with ERROR nodes
    assert tree.root_node is not None
    # We expect either has_error or ERROR in children when input is invalid
    if tree.root_node.has_error:
        assert "error" in caplog.text.lower() or "Parse" in caplog.text


def test_parse_file_sample_c():
    """Parser parses the small C sample file successfully."""
    sample_path = Path(__file__).parent / "sample.c"
    assert sample_path.exists(), "tests/sample.c must exist"
    tree = parse_file(sample_path)
    assert tree is not None
    assert tree.root_node is not None
    assert not tree.root_node.has_error
    assert tree.root_node.type == "translation_unit"


def test_parse_file_nonexistent(caplog):
    """parse_file() on nonexistent path returns None and logs error."""
    with caplog.at_level(logging.ERROR):
        tree = parse_file(Path("/nonexistent/sample.c"))
    assert tree is None
    assert "Failed to read" in caplog.text or "nonexistent" in caplog.text
