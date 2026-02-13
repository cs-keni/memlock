# Hardcoded secrets detection: detects passwords, API keys, and tokens in source code

from __future__ import annotations

from typing import Any

from scanner.findings.models import Finding
from scanner.rules.base import Rule


class HardcodedSecretsRule(Rule):
    """
    Detects hardcoded secrets: passwords, API keys, tokens in string literals.
    TODO: Implement - see project-idea.md for AST targets and strategy.
    """

    id = "hardcoded-secrets"
    name = "Hardcoded secrets"

    def run(self, context: Any, config: Any) -> list[Finding]:
        # Stub: implement to flag string literals matching secret patterns.
        return []
