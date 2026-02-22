# Unsafe function usage detection: detects calls to dangerous standard library functions

from __future__ import annotations

import re
from typing import Any

from tree_sitter import Node as TSNode

from scanner.context import FileContext, get_line_col, get_source_span
from scanner.findings.models import Finding, Location
from scanner.rules.base import Rule

# Classic C functions that are always unsafe (no bounds checking)
ALWAYS_UNSAFE = frozenset(
    {
        "gets",  # no bounds; removed in C11
        "strcpy",  # no bounds
        "strcat",  # no bounds
        "sprintf",  # no bounds
        "vsprintf",  # no bounds
        "getwd",  # buffer overflow risk
        "tmpnam",  # race / buffer issues
    }
)

# scanf/sscanf: unsafe only when format has unbounded %s or %[...]
SCANF_LIKE = frozenset({"scanf", "sscanf"})


def _scanf_format_has_unbounded_string(fmt: str) -> bool:
    """True if format contains %s or %[ without width (e.g. %15s is safe)."""
    s = fmt.replace("%%", "")
    for m in re.finditer(r"%(?:\*?)((?:\d+)?)(?:hh|h|ll|l|j|z|t|L)?([s\[])", s):
        if m.group(1) == "" and m.group(2) in ("s", "["):
            return True
    return False


def _unquote_c_string(raw: str) -> str | None:
    """Extract body from C string literal, or None if not a simple literal."""
    raw = raw.strip()
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return None
    return raw[1:-1]  # good enough for format string scanning


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
            if not name:
                continue

            # Always-unsafe functions
            if name in ALWAYS_UNSAFE:
                line, col = get_line_col(node)
                findings.append(
                    Finding(
                        rule_id=self.id,
                        message=f"Unsafe function '{name}' may lead to buffer overflow or undefined behavior; use a safe alternative.",
                        location=Location(
                            path=context.path,
                            line=line,
                            column=col,
                            snippet=get_source_span(context, node),
                        ),
                        severity="warning",
                    )
                )
                continue

            # scanf/sscanf: only flag if format has unbounded %s or %[...]
            if name in SCANF_LIKE:
                args = node.child_by_field_name("arguments")
                named = [c for c in args.children] if args else []
                named = [c for c in named if getattr(c, "is_named", False)]
                fmt_idx = 1 if name == "sscanf" and len(named) > 1 else 0
                if fmt_idx < len(named):
                    fmt_node = named[fmt_idx]
                    if fmt_node.type == "string_literal":
                        fmt_raw = get_source_span(context, fmt_node)
                        fmt = _unquote_c_string(fmt_raw)
                        if fmt is not None and not _scanf_format_has_unbounded_string(
                            fmt
                        ):
                            continue  # bounded format, don't flag
                line, col = get_line_col(node)
                findings.append(
                    Finding(
                        rule_id=self.id,
                        message=f"Unsafe function '{name}' may lead to buffer overflow or undefined behavior; use a safe alternative.",
                        location=Location(
                            path=context.path,
                            line=line,
                            column=col,
                            snippet=get_source_span(context, node),
                        ),
                        severity="warning",
                    )
                )
        return findings
