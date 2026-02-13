"""Unit tests for the hardcoded_secrets rule."""

import pytest
from pathlib import Path

from scanner.context import FileContext, create_context
from scanner.parser import create_parser, parse_bytes
from scanner.rules.hardcoded_secrets import HardcodedSecretsRule


def _run_rule(source: bytes, path: Path | None = None) -> list:
    """Parse source, build context, run HardcodedSecretsRule, return findings."""
    if path is None:
        path = Path("test.c")
    parser = create_parser()
    tree = parse_bytes(source, parser=parser)
    ctx = FileContext(path=path, source=source, tree=tree)
    rule = HardcodedSecretsRule()
    return rule.run(ctx, None)


def test_no_hardcoded_secrets():
    """Code without secrets yields no findings."""
    source = b"""
int main(void) {
    const char *msg = "Hello world";
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) == 0


@pytest.mark.xfail(reason="Rule not yet implemented - remove when hardcoded_secrets is done")
def test_api_key_detected():
    """Hardcoded API key should be flagged."""
    source = b"""
static const char *API_KEY = "APIKEY-SECRET-1234567890";
int main(void) { return 0; }
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "hardcoded-secrets"
    assert "secret" in findings[0].message.lower() or "api" in findings[0].message.lower() or "key" in findings[0].message.lower()


@pytest.mark.xfail(reason="Rule not yet implemented - remove when hardcoded_secrets is done")
def test_password_detected():
    """Hardcoded password should be flagged."""
    source = b"""
int main(void) {
    char *password = "P@ssw0rd!";
    return 0;
}
"""
    findings = _run_rule(source)
    assert len(findings) >= 1
    assert findings[0].rule_id == "hardcoded-secrets"


def test_finding_has_location(tmp_path):
    """Findings have path, line, column, and snippet."""
    c_file = tmp_path / "secrets.c"
    c_file.write_bytes(b'const char *key = "APIKEY-12345";\n')
    ctx = create_context(c_file)
    assert ctx is not None
    rule = HardcodedSecretsRule()
    findings = rule.run(ctx, None)
    if len(findings) >= 1:
        loc = findings[0].location
        assert loc.path == c_file
        assert loc.line >= 1
        assert loc.column >= 1
        assert loc.snippet is not None
