# Buffer overflow risk detection: detects array bounds violations and unsafe buffer operations

from __future__ import annotations

from typing import Any

from scanner.findings.models import Finding
from scanner.rules.base import Rule


class BufferOverflowRule(Rule):
    """
    Detects buffer overflow risks: out-of-bounds writes, loops exceeding array size.
    TODO: Implement - see project-idea.md for AST targets and strategy.
    """

    id = "buffer-overflow"
    name = "Buffer overflow risk"

    def run(self, context: Any, config: Any) -> list[Finding]:
        # Stub: implement to flag array bounds violations, out-of-bounds writes.
        return []
