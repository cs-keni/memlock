# Rule interface (abstract base class): defines the contract all rules must implement.
# Concrete rules (buffer_overflow, format_string, etc.) subclass Rule and implement run().

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

# Context/config/findings are typed as Any until those modules exist.
# Contract: context is FileContext (path, source, tree), config is Config,
# return type is list[Finding].


class Rule(ABC):
    """
    Abstract base class for all static analysis rules.

    Subclasses must define:
    - id: str — unique rule identifier (e.g. "buffer-overflow")
    - name: str — human-readable rule name (e.g. "Buffer overflow risk")
    - run(context, config) -> list[Finding] — analyze one file and return findings

    The scanner calls run() once per file; context holds path, source bytes, and AST.
    """

    id: str
    name: str

    @abstractmethod
    def run(self, context: Any, config: Any) -> list[Any]:
        """
        Analyze one file and return any findings.

        Args:
            context: Per-file state (path, source bytes, AST tree). Use context.tree
                     to walk the AST and context.source / helpers for snippets.
                     Type: FileContext (from scanner.context, when implemented).
            config: Scanner config (enabled rules, severity map, etc.).
                    Type: Config (from scanner.config, when implemented).

        Returns:
            List of Finding objects for each issue found in this file.
            Return an empty list if no issues. Type: list[Finding].
        """
        ...
