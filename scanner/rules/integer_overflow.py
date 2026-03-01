# Integer overflow/underflow detection: detects arithmetic operations without bounds checks

from __future__ import annotations

"""
Integer overflow/underflow detection: flag arithmetic expressions on integers
that are not obviously guarded by a bounds check.

Heuristics:

- looking for binary_expression with operators: +, -, *, /, %, <<, >>

- ignore expressions without variables

- considers the arithmetic guarded if it is preceded by an if statement with a
    relational operator ot limit macros (INT_MAX, etc)
"""

from typing import Any, Iterable, Set

from tree_sitter import Node as TSNode

from scanner.context import FileContext, get_line_col, get_source_span
from scanner.findings.models import Finding, Location
from scanner.rules.base import Rule


ARITHMETIC_OPERATORS: tuple[str, ...] = ("<<", ">>", "+", "-", "*", "/", "%")
COMPARISON_OPERATORS: tuple[str, ...] = ("<=", ">=", "<", ">")
LIMIT_MACROS: tuple[str, ...] = (
    "INT_MAX",
    "UINT_MAX",
    "SIZE_MAX",
    "LONG_MAX",
    "ULONG_MAX",
    "SHRT_MAX",
    "USHRT_MAX",
    "INT_MIN",
    "LONG_MIN",
)


def _walk(node: TSNode) -> Iterable[TSNode]:
    yield node
    for child in node.children:
        yield from _walk(child)


def _collect_identifiers(context: FileContext, node: TSNode, acc: Set[str] | None = None) -> Set[str]:

    if acc is None:
        acc = set()
    if node.type == "identifier":
        name = get_source_span(context, node).strip()
        if name:
            acc.add(name)
    for child in node.children:
        _collect_identifiers(context, child, acc)
    return acc


def _is_arithmetic_expression(context: FileContext, node: TSNode) -> bool:
    if node.type != "binary_expression":
        return False
    text = get_source_span(context, node)
    return any(op in text for op in ARITHMETIC_OPERATORS)


def _condition_has_bounds_check_for(
    context: FileContext,
    condition: TSNode,
    var_names: Set[str],
) -> bool:
    for node in _walk(condition):
        if node.type != "binary_expression":
            continue
        text = get_source_span(context, node)
        if not any(name in text for name in var_names):
            continue
        if any(op in text for op in COMPARISON_OPERATORS):
            return True
        if any(limit in text for limit in LIMIT_MACROS):
            return True
    return False


def _is_protected_by_bounds_check(context: FileContext, expr_node: TSNode, var_names: Set[str]) -> bool:
    parent = expr_node.parent
    while parent is not None:
        if parent.type == "if_statement":
            cond = parent.child_by_field_name("condition")
            if cond is None and parent.child_count >= 2:
                # Defensive fallback: in the C grammar, the condition is usually
                # accessible via child_by_field_name, but we grab the second
                # child if needed.
                cond = parent.child(1)
            if cond is not None and _condition_has_bounds_check_for(context, cond, var_names):
                return True
        # Stop once we leave the function body
        if parent.type in {"function_definition", "translation_unit"}:
            break
        parent = parent.parent
    return False


class IntegerOverflowRule(Rule):
    """
    Detect arithmetic operations that appear to lack surrounding bounds checks.
    """

    id = "integer-overflow"
    name = "Potential integer overflow / underflow"

    def run(self, context: Any, config: Any) -> list[Any]:
        findings: list[Finding] = []
        file_ctx: FileContext = context  # for type checkers / clarity
        root = file_ctx.root_node

        for node in _walk(root):
            if not _is_arithmetic_expression(file_ctx, node):
                continue

            var_names = _collect_identifiers(file_ctx, node)
            # Ignore expressions with no identifiers (e.g. 1 + 2).
            if not var_names:
                continue

            if _is_protected_by_bounds_check(file_ctx, node, var_names):
                continue

            line, col = get_line_col(node)
            location = Location(
                path=file_ctx.path,
                line=line,
                column=col,
                snippet=get_source_span(file_ctx, node),
            )
            findings.append(
                Finding(
                    rule_id=self.id,
                    message=(
                        "Arithmetic expression may overflow or underflow without an "
                        "obvious surrounding bounds check on involved variables."
                    ),
                    location=location,
                    severity="warning",
                )
            )

        return findings
