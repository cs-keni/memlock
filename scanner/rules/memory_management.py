# Memory management error detection: detects memory leaks, double free, and missing free

from __future__ import annotations

from typing import Any

from scanner.findings.models import Finding
from scanner.rules.base import Rule


class MemoryManagementRule(Rule):
    """
    Detects memory management errors: leaks (malloc without free), double free.
    TODO: Implement - see project-idea.md for AST targets and strategy.
    """

    id = "memory-management"
    name = "Memory management error"

    def run(self, context: Any, config: Any) -> list[Finding]:
        # Stub: implement to flag leaks and double free.
        return []
