from __future__ import annotations

"""
Scanner configuration: which rules are enabled and how they are instantiated.

Right now this is intentionally minimal – it just registers the rules that
are implemented (unsafe functions and use-after-free). As we add more rules
and features (per-rule severity, enable/disable flags, etc.) this module is
the single place to update.
"""

from dataclasses import dataclass, field
from typing import Iterable, List, Sequence

from scanner.rules.base import Rule
from scanner.rules.unsafe_functions import UnsafeFunctionsRule
from scanner.rules.use_after_free import UseAfterFreeRule


@dataclass
class Config:
    """
    Scanner configuration.

    For now it only carries the list of enabled rules. Later we can extend
    this with severity mappings, file include/exclude patterns, etc.
    """

    rules: Sequence[Rule] = field(default_factory=list)


def get_default_config() -> Config:
    """
    Return the default configuration with all currently implemented rules.

    This is what the CLI in main.py uses unless we add CLI flags or config
    files to customize it.
    """
    rules: List[Rule] = [
        UnsafeFunctionsRule(),
        UseAfterFreeRule(),
    ]
    return Config(rules=rules)


def get_enabled_rules(config: Config | None = None) -> Sequence[Rule]:
    """
    Return the list of enabled rules from the given config (or default config).

    This helper keeps main.py simple and gives us a single place to later add
    filtering logic (e.g. by severity or rule id).
    """
    if config is None:
        config = get_default_config()
    return config.rules

# Configuration management: enabled rules, severity mapping, and filter settings.

def placeholder() -> None:
    """Placeholder function to keep module tracked."""
    return None
