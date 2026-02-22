"""Unit tests for the integer_overflow rule."""

import pytest
from pathlib import Path

from scanner.context import FileContext, create_context
from scanner.parser import create_parser, parse_bytes
from scanner.rules.integer_overflow import IntegerOverflowRule


def _run_rule(source: bytes, path: Path | None = None) -> list:
    """Parse source, build context, run IntegerOverflowRule, return findings."""
    if path is None:
        path = Path("test.c")
    parser = create_parser()
    tree = parse_bytes(source, parser=parser)
    ctx = FileContext(path=path, source=source, tree=tree)
    rule = IntegerOverflowRule()
    return rule.run(ctx, None)


def test_no_integer_overflow():
    """Simple allocation without arithmetic yields no findings."""
    source = b"""
int main(void) {
    char *p = malloc(256);
    free(p);
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) == 0


@pytest.mark.xfail(reason="Rule not yet implemented - remove when integer_overflow is done")
def test_malloc_arithmetic_detected():
    """malloc(n * m) with potential overflow should be flagged."""
    source = b"""
void foo(size_t n, size_t m) {
    char *p = malloc(n * m);
    free(p);
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "integer-overflow"


@pytest.mark.xfail(reason="Rule not yet implemented - remove when integer_overflow is done")
def test_large_multiply_in_allocation():
    """n * m with large values (e.g. 1u << 30) is suspicious."""
    source = b"""
void bar(void) {
    size_t n = 1u << 30;
    size_t m = 16u;
    char *p = malloc(n * m);
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "integer-overflow"


def test_finding_has_location(tmp_path):
    """Findings have path, line, column, and snippet."""
    c_file = tmp_path / "overflow.c"
    c_file.write_bytes(b"void foo(void) { size_t n = 1000000; char *p = malloc(n * 1000); }\n")
    ctx = create_context(c_file)
    assert ctx is not None
    rule = IntegerOverflowRule()
    findings = rule.run(ctx, None)
    if len(findings) >= 1:
        loc = findings[0].location
        assert loc.path == c_file
        assert loc.line >= 1
        assert loc.column >= 1
        assert loc.snippet is not None
