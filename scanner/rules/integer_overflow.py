# Integer overflow/underflow detection: detects arithmetic operations without bounds checks

from __future__ import annotations

"""
Integer overflow/underflow detection: flag arithmetic expressions on integers
that are not obviously guarded by a bounds check.

Heuristics:

- looking for binary_expression with operators: +, -, *, /, %, <<, >>

- ignore expressions without variables

- considers the arithmetic guarded if it is preceded by an if statement with a
    relational operator or limit macros (INT_MAX, etc)
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


def _is_descendant_of(desc: TSNode, anc: TSNode) -> bool:
    n = desc
    while n is not None:
        if n == anc:
            return True
        n = n.parent
    return False


def _extract_lhs_identifier(context: FileContext, node: TSNode) -> str | None:
    """If node is RHS of assignment or init, return LHS identifier name."""
    parent = node.parent
    while parent is not None:
        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            right = parent.child_by_field_name("right")
            if left is not None and right is not None and _is_descendant_of(node, right):
                for child in _walk(left):
                    if child.type == "identifier":
                        return get_source_span(context, child).strip()
            return None
        if parent.type == "init_declarator":
            decl = parent.child_by_field_name("declarator")
            value = parent.child_by_field_name("value") or parent.child_by_field_name("initializer")
            if decl is not None and value is not None and _is_descendant_of(node, value):
                for child in _walk(decl):
                    if child.type == "identifier":
                        return get_source_span(context, child).strip()
            return None
        if parent.type in {"function_definition", "translation_unit", "compound_statement"}:
            return None
        parent = parent.parent
    return None


def _contains_sizeof(node: TSNode) -> bool:
    """True if this node or any descendant is a sizeof_expression."""
    if node.type == "sizeof_expression":
        return True
    for child in node.children:
        if _contains_sizeof(child):
            return True
    return False


def _get_binary_operator(context: FileContext, node: TSNode) -> str | None:
    """Return the operator of a binary_expression, or None."""
    if node.type != "binary_expression" or node.child_count < 3:
        return None
    # Operator is typically the middle child (left, op, right)
    op_node = node.child(1)
    if op_node is None:
        return None
    return get_source_span(context, op_node).strip()


def _is_arithmetic_expression(context: FileContext, node: TSNode) -> bool:
    if node.type != "binary_expression":
        return False
    op = _get_binary_operator(context, node)
    return op is not None and op in ARITHMETIC_OPERATORS


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
                cond = parent.child(1)
            if cond is not None and _condition_has_bounds_check_for(context, cond, var_names):
                return True
        if parent.type == "compound_statement":
            # Arithmetic may be in declaration/assignment; check subsequent siblings for bounds check
            children = parent.children
            for i, child in enumerate(children):
                if not _is_descendant_of(expr_node, child):
                    continue
                for j in range(i + 1, len(children)):
                    sib = children[j]
                    if sib.type != "if_statement":
                        continue
                    cond = sib.child_by_field_name("condition")
                    if cond is None and sib.child_count >= 2:
                        cond = sib.child(1)
                    if cond is not None and _condition_has_bounds_check_for(context, cond, var_names):
                        return True
                break
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

            # Skip sizeof-based arithmetic (e.g. sizeof(buf) - 1) - compile-time safe
            if _contains_sizeof(node):
                continue

            var_names = _collect_identifiers(file_ctx, node)
            # Ignore expressions with no identifiers (e.g. 1 + 2).
            if not var_names:
                continue

            # If arithmetic is RHS of assignment/init, LHS is the result variable;
            # bounds check on result (e.g. "if (total > 1024)") counts as protection
            lhs = _extract_lhs_identifier(file_ctx, node)
            if lhs:
                var_names = var_names | {lhs}

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
