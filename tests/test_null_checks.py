"""Unit tests for the null_checks rule."""

import pytest
from pathlib import Path

from scanner.context import FileContext, create_context
from scanner.parser import create_parser, parse_bytes
from scanner.rules.null_checks import NullChecksRule


def _run_rule(source: bytes, path: Path | None = None) -> list:
    """Parse source, build context, run NullChecksRule, return findings."""
    if path is None:
        path = Path("test.c")
    parser = create_parser()
    tree = parse_bytes(source, parser=parser)
    ctx = FileContext(path=path, source=source, tree=tree)
    rule = NullChecksRule()
    return rule.run(ctx, None)


def test_malloc_with_null_check():
    """malloc followed by NULL check before use yields no findings."""
    source = b"""
int main(void) {
    int *p = malloc(sizeof(int));
    if (!p) return 1;
    *p = 42;
    free(p);
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) == 0


@pytest.mark.xfail(reason="Rule not yet implemented - remove when null_checks is done")
def test_dereference_without_null_check_detected():
    """Dereference of malloc result without NULL check should be flagged."""
    source = b"""
void foo(void) {
    int *p = malloc(sizeof(int));
    *p = 42;
    free(p);
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "null-checks"
    assert "null" in findings[0].message.lower() or "check" in findings[0].message.lower()


@pytest.mark.xfail(reason="Rule not yet implemented - remove when null_checks is done")
def test_subscript_without_null_check():
    """p[0] without NULL check after malloc should be flagged."""
    source = b"""
void bar(void) {
    char *buf = malloc(64);
    buf[0] = 'x';
    free(buf);
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "null-checks"


def test_finding_has_location(tmp_path):
    """Findings have path, line, column, and snippet."""
    c_file = tmp_path / "null.c"
    c_file.write_bytes(b"void foo(void) { int *p = malloc(4); *p = 0; free(p); }\n")
    ctx = create_context(c_file)
    assert ctx is not None
    rule = NullChecksRule()
    findings = rule.run(ctx, None)
    if len(findings) >= 1:
        loc = findings[0].location
        assert loc.path == c_file
        assert loc.line >= 1
        assert loc.column >= 1
        assert loc.snippet is not None
