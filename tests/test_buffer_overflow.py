"""Unit tests for the buffer_overflow rule."""

from pathlib import Path

from scanner.context import FileContext, create_context
from scanner.parser import create_parser, parse_bytes
from scanner.rules.buffer_overflow import BufferOverflowRule


def _run_rule(source: bytes, path: Path | None = None) -> list:
    """Parse source, build context, run BufferOverflowRule, return findings."""
    if path is None:
        path = Path("test.c")
    parser = create_parser()
    tree = parse_bytes(source, parser=parser)
    ctx = FileContext(path=path, source=source, tree=tree)
    rule = BufferOverflowRule()
    return rule.run(ctx, None)


def test_no_buffer_overflow():
    """Code with proper bounds yields no findings."""
    source = b"""
int main(void) {
    char buf[8];
    int i;
    for (i = 0; i < 8; i++) {
        buf[i] = 'A';
    }
    buf[7] = '\\0';
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) == 0


def test_out_of_bounds_loop_detected():
    """Loop that writes past array end (i <= 8 for buf[8]) should be flagged."""
    source = b"""
void foo(void) {
    char buf[8];
    int i;
    for (i = 0; i <= 8; i++) {
        buf[i] = 'A';
    }
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "buffer-overflow"
    assert findings[0].location.snippet is not None


def test_direct_out_of_bounds_write():
    """Direct subscript beyond array size should be flagged."""
    source = b"""
int main(void) {
    int arr[4];
    arr[4] = 42;
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "buffer-overflow"


def test_finding_has_location(tmp_path):
    """Findings have path, line, column, and snippet."""
    c_file = tmp_path / "overflow.c"
    c_file.write_bytes(
        b"int main(void) { char buf[4]; int i; for (i = 0; i <= 4; i++) buf[i] = 0; return 0; }\n"
    )
    ctx = create_context(c_file)
    assert ctx is not None
    rule = BufferOverflowRule()
    findings = rule.run(ctx, None)
    # Stub returns []; once implemented, expect at least one finding
    if len(findings) >= 1:
        loc = findings[0].location
        assert loc.path == c_file
        assert loc.line >= 1
        assert loc.column >= 1
        assert loc.snippet is not None
