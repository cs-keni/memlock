# Integer overflow/underflow detection: detects arithmetic operations without bounds checks

from __future__ import annotations

from typing import Any

from scanner.findings.models import Finding
from scanner.rules.base import Rule


class IntegerOverflowRule(Rule):
    """
    Detects integer overflow/underflow: arithmetic in malloc size, unbounded multiplies.
    TODO: Implement - see project-idea.md for AST targets and strategy.
    """

    id = "integer-overflow"
    name = "Integer overflow/underflow"

    def run(self, context: Any, config: Any) -> list[Finding]:
        # Stub: implement to flag suspicious arithmetic without bounds checks.
        return []
