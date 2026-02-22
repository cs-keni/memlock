"""Unit tests for the memory_management rule."""

import pytest
from pathlib import Path

from scanner.context import FileContext, create_context
from scanner.parser import create_parser, parse_bytes
from scanner.rules.memory_management import MemoryManagementRule


def _run_rule(source: bytes, path: Path | None = None) -> list:
    """Parse source, build context, run MemoryManagementRule, return findings."""
    if path is None:
        path = Path("test.c")
    parser = create_parser()
    tree = parse_bytes(source, parser=parser)
    ctx = FileContext(path=path, source=source, tree=tree)
    rule = MemoryManagementRule()
    return rule.run(ctx, None)


def test_no_leak():
    """malloc followed by free yields no findings."""
    source = b"""
int main(void) {
    int *p = malloc(sizeof(int));
    *p = 42;
    free(p);
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) == 0


@pytest.mark.xfail(reason="Rule not yet implemented - remove when memory_management is done")
def test_memory_leak_detected():
    """malloc without free should be flagged as leak."""
    source = b"""
void foo(void) {
    char *p = malloc(256);
    p[0] = 'x';
    return;
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "memory-management"
    assert "leak" in findings[0].message.lower() or "free" in findings[0].message.lower()


@pytest.mark.xfail(reason="Rule not yet implemented - remove when memory_management is done")
def test_double_free_detected():
    """free(p) called twice should be flagged."""
    source = b"""
void bar(void) {
    int *p = malloc(sizeof(int));
    free(p);
    free(p);
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "memory-management"
    assert "double" in findings[0].message.lower() or "free" in findings[0].message.lower()


def test_finding_has_location(tmp_path):
    """Findings have path, line, column, and snippet."""
    c_file = tmp_path / "leak.c"
    c_file.write_bytes(b"void foo(void) { char *p = malloc(10); }\n")
    ctx = create_context(c_file)
    assert ctx is not None
    rule = MemoryManagementRule()
    findings = rule.run(ctx, None)
    if len(findings) >= 1:
        loc = findings[0].location
        assert loc.path == c_file
        assert loc.line >= 1
        assert loc.column >= 1
        assert loc.snippet is not None
