# Missing NULL check detection: detects dereferencing pointers without NULL validation

from __future__ import annotations

from typing import Any

from scanner.findings.models import Finding
from scanner.rules.base import Rule


class NullChecksRule(Rule):
    """
    Detects missing NULL checks: dereference of malloc result without NULL guard.
    TODO: Implement - see project-idea.md for AST targets and strategy.
    """

    id = "null-checks"
    name = "Missing NULL check"

    def run(self, context: Any, config: Any) -> list[Finding]:
        # Stub: implement to flag dereferences without NULL validation.
        return []
