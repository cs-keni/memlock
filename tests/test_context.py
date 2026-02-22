"""Tests for scanner.context: FileContext, create_context, load_contexts, node/function counts."""

from pathlib import Path

from scanner.context import (
    FileContext,
    count_tree_stats,
    create_context,
    get_line_col,
    get_source_span,
    load_contexts,
)
from scanner.parser import create_parser, parse_bytes


def test_count_tree_stats():
    parser = create_parser()
    tree = parse_bytes(b"int main(void) { return 0; }", parser=parser)
    nodes, funcs = count_tree_stats(tree.root_node)
    assert nodes >= 1
    assert funcs == 1


def test_create_context_sample_c(tmp_path):
    c_file = tmp_path / "main.c"
    c_file.write_bytes(b"int main(void) { return 0; }\n")
    ctx = create_context(c_file)
    assert ctx is not None
    assert ctx.path == c_file
    assert ctx.source == b"int main(void) { return 0; }\n"
    assert ctx.tree is not None
    assert ctx.tree.root_node is not None
    assert ctx.has_parse_errors is False


def test_create_context_nonexistent():
    ctx = create_context(Path("/nonexistent/file.c"))
    assert ctx is None


def test_create_context_malformed_still_returns_context(tmp_path):
    c_file = tmp_path / "bad.c"
    c_file.write_bytes(b"int main( { return 0; }\n")  # missing )
    ctx = create_context(c_file)
    assert ctx is not None
    assert ctx.has_parse_errors is True


def test_get_source_span():
    parser = create_parser()
    tree = parse_bytes(b"int x = 42;", parser=parser)
    ctx = FileContext(path=Path("x.c"), source=b"int x = 42;", tree=tree)
    root = ctx.tree.root_node
    span = get_source_span(ctx, root)
    assert "int" in span or "42" in span


def test_get_line_col_one_based():
    parser = create_parser()
    tree = parse_bytes(b"int x;\nint y;", parser=parser)
    root = tree.root_node
    line, col = get_line_col(root, one_based=True)
    assert line >= 1
    assert col >= 1


def test_load_contexts(tmp_path):
    a = tmp_path / "a.c"
    b = tmp_path / "b.c"
    a.write_bytes(b"int main(void) { return 0; }\n")
    b.write_bytes(b"void foo(void) { }\n")
    contexts = load_contexts([a, b])
    assert len(contexts) == 2
    assert contexts[0].path == a
    assert contexts[1].path == b


def test_load_contexts_skips_unreadable(tmp_path):
    a = tmp_path / "a.c"
    a.write_bytes(b"int main(void) { return 0; }\n")
    contexts = load_contexts([a, tmp_path / "missing.c"])
    assert len(contexts) == 1
    assert contexts[0].path == a
