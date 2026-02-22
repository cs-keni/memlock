"""Unit tests for the unsafe_functions rule."""

from pathlib import Path

from scanner.context import FileContext, create_context
from scanner.parser import create_parser, parse_bytes
from scanner.rules.unsafe_functions import UnsafeFunctionsRule


def _run_rule(source: bytes, path: Path | None = None) -> list:
    """Parse source, build context, run UnsafeFunctionsRule, return findings."""
    if path is None:
        path = Path("test.c")
    parser = create_parser()
    tree = parse_bytes(source, parser=parser)
    ctx = FileContext(path=path, source=source, tree=tree)
    rule = UnsafeFunctionsRule()
    return rule.run(ctx, None)


def test_no_unsafe_functions():
    """Code with no unsafe functions yields no findings."""
    source = b"""
int main(void) {
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) == 0


def test_gets_detected():
    """gets() is reported as unsafe."""
    source = b"int main(void) { char b[64]; gets(b); return 0; }"
    findings = _run_rule(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "unsafe-functions"
    assert "gets" in findings[0].message
    assert findings[0].location.snippet is not None
    assert "gets" in findings[0].location.snippet


def test_strcpy_detected():
    """strcpy() is reported as unsafe."""
    source = b"int main(void) { char a[8], b[8]; strcpy(a, b); return 0; }"
    findings = _run_rule(source)
    assert len(findings) == 1
    assert findings[0].rule_id == "unsafe-functions"
    assert "strcpy" in findings[0].message


def test_sprintf_detected():
    """sprintf() is reported as unsafe."""
    source = b'int main(void) { char buf[32]; sprintf(buf, "%d", 42); return 0; }'
    findings = _run_rule(source)
    assert len(findings) == 1
    assert "sprintf" in findings[0].message


def test_multiple_unsafe_functions():
    """Multiple unsafe calls produce multiple findings."""
    source = b"""
void foo(void) {
    char a[8], b[8];
    gets(a);
    strcpy(b, a);
    sprintf(a, "x");
}
"""
    findings = _run_rule(source)
    assert len(findings) == 3
    rule_ids = [f.rule_id for f in findings]
    assert all(r == "unsafe-functions" for r in rule_ids)
    messages = " ".join(f.message for f in findings)
    assert "gets" in messages
    assert "strcpy" in messages
    assert "sprintf" in messages


def test_safe_alternatives_not_flagged():
    """Safe functions (snprintf, strncpy, fgets) are not flagged."""
    source = b"""
int main(void) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%d", 42);
    fgets(buf, sizeof(buf), stdin);
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) == 0


def test_scanf_with_width_not_flagged():
    """scanf with bounded format (e.g. %15s) is not flagged."""
    source = b'int main(void) { char name[16]; scanf("%15s", name); return 0; }'
    findings = _run_rule(source)
    assert len(findings) == 0


def test_finding_has_location(tmp_path):
    """Findings have path, line, column, and snippet."""
    c_file = tmp_path / "main.c"
    c_file.write_bytes(b"int main(void) { gets(0); return 0; }\n")
    ctx = create_context(c_file)
    assert ctx is not None
    rule = UnsafeFunctionsRule()
    findings = rule.run(ctx, None)
    assert len(findings) == 1
    loc = findings[0].location
    assert loc.path == c_file
    assert loc.line >= 1
    assert loc.column >= 1
    assert loc.snippet is not None
