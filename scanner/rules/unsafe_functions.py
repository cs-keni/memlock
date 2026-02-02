# Unsafe function usage detection: detects calls to dangerous standard library functions

from __future__ import annotations

from typing import Any

from tree_sitter import Node as TSNode

from scanner.context import FileContext, get_line_col, get_source_span
from scanner.findings.models import Finding, Location
from scanner.rules.base import Rule

# Classic C functions that are unsafe (no bounds checking or known to be misused)
UNSAFE_FUNCTIONS = frozenset({
    "gets",       # no bounds; removed in C11
    "strcpy",     # no bounds
    "strcat",     # no bounds
    "sprintf",    # no bounds
    "vsprintf",   # no bounds
    "scanf",      # %s without width is unsafe
    "sscanf",     # same
    "getwd",      # buffer overflow risk
    "tmpnam",     # race / buffer issues
})


def _walk(node: TSNode):
    """Yield every descendant of node in document order (DFS)."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _get_called_function_name(context: FileContext, call_node: TSNode) -> str | None:
    """
    Return the bare function name for a call_expression, or None.
    Handles identifier (e.g. gets, strcpy) and field_expression (e.g. obj.foo).
    """
    if call_node.type != "call_expression" or call_node.child_count == 0:
        return None
    func_node = call_node.child(0)
    if func_node is None:
        return None
    if func_node.type == "identifier":
        return get_source_span(context, func_node).strip()
    if func_node.type == "field_expression":
        # e.g. foo.bar() -> we care about "bar"
        for i in range(func_node.child_count - 1, -1, -1):
            c = func_node.child(i)
            if c and c.type == "identifier":
                return get_source_span(context, c).strip()
        return None
    return get_source_span(context, func_node).strip()


class UnsafeFunctionsRule(Rule):
    """Detects calls to dangerous C standard library functions (e.g. gets, strcpy)."""

    id = "unsafe-functions"
    name = "Unsafe function usage"

    def run(self, context: Any, config: Any) -> list[Any]:
        findings: list[Finding] = []
        root = context.root_node
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            name = _get_called_function_name(context, node)
            if name and name in UNSAFE_FUNCTIONS:
                line, col = get_line_col(node)
                location = Location(
                    path=context.path,
                    line=line,
                    column=col,
                    snippet=get_source_span(context, node),
                )
                findings.append(
                    Finding(
                        rule_id=self.id,
                        message=f"Unsafe function '{name}' may lead to buffer overflow or undefined behavior; use a safe alternative.",
                        location=location,
                        severity="warning",
                    )
                )
        return findings
