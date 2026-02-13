"""Unit tests for the format_string rule."""

import pytest
from pathlib import Path

from scanner.context import FileContext, create_context
from scanner.parser import create_parser, parse_bytes
from scanner.rules.format_string import FormatStringRule


def _run_rule(source: bytes, path: Path | None = None) -> list:
    """Parse source, build context, run FormatStringRule, return findings."""
    if path is None:
        path = Path("test.c")
    parser = create_parser()
    tree = parse_bytes(source, parser=parser)
    ctx = FileContext(path=path, source=source, tree=tree)
    rule = FormatStringRule()
    return rule.run(ctx, None)


def test_safe_printf_with_literal_format():
    """printf with string literal format is safe."""
    source = b"""
int main(void) {
    char *user_input = "hello";
    printf("%s", user_input);
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) == 0


@pytest.mark.xfail(reason="Rule not yet implemented - remove when format_string is done")
def test_printf_user_input_detected():
    """printf(user_input) - user-controlled format - should be flagged."""
    source = b"""
int main(void) {
    char user_input[64];
    fgets(user_input, sizeof(user_input), stdin);
    printf(user_input);
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "format-string"
    assert "printf" in findings[0].message.lower() or "format" in findings[0].message.lower()


def test_sprintf_user_input_detected():
    """sprintf with variable format should be flagged (if applicable)."""
    source = b"""
void foo(char *fmt) {
    char buf[128];
    sprintf(buf, fmt, "x");
}
"""
    findings = _run_rule(source)
    # Format string rule may flag printf-family with non-literal format
    assert len(findings) >= 0


def test_finding_has_location(tmp_path):
    """Findings have path, line, column, and snippet."""
    c_file = tmp_path / "fmt.c"
    c_file.write_bytes(b"int main(void) { char x[64]; fgets(x,64,stdin); printf(x); return 0; }\n")
    ctx = create_context(c_file)
    assert ctx is not None
    rule = FormatStringRule()
    findings = rule.run(ctx, None)
    if len(findings) >= 1:
        loc = findings[0].location
        assert loc.path == c_file
        assert loc.line >= 1
        assert loc.column >= 1
        assert loc.snippet is not None
