# Format string vulnerability detection: detects unsafe printf-style functions with user input

from __future__ import annotations

from typing import Any

from scanner.findings.models import Finding
from scanner.rules.base import Rule


class FormatStringRule(Rule):
    """
    Detects format string vulnerabilities: printf(user_input) where format is not a literal.
    TODO: Implement - see project-idea.md for AST targets and strategy.
    """

    id = "format-string"
    name = "Format string vulnerability"

    def run(self, context: Any, config: Any) -> list[Finding]:
        # Stub: implement to flag printf/sprintf with non-literal format argument.
        return []
