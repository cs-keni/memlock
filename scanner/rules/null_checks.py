# Missing NULL check detection: detects dereferencing pointers without NULL validation

from __future__ import annotations

"""
Missing NULL check detection: flag pointer dereferences that are not obviously
guarded by a preceding NULL check.

- Treat the following as pointer dereferences:
  - unary '*' and '->' member access (tree-sitter-c: both are pointer_expression; *p and p->field)
  - array subscript (array_subscript_expression, e.g. p[i])
- Consider a dereference "guarded" if:
    - it is inside an `if (ptr != NULL)` then-branch, or
    - it is inside an `if (!ptr)` or `if (ptr == NULL)` else-branch, or
    - it appears after a preceding `if (!ptr) return ...` / `if (ptr == NULL) return ...`
      in the same block.
"""

from typing import Any

from tree_sitter import Node as TSNode

from scanner.context import FileContext, get_line_col, get_source_span
from scanner.findings.models import Finding, Location
from scanner.rules.base import Rule


def _walk(node: TSNode):
    yield node
    for child in node.children:
        yield from _walk(child)


def _extract_identifier_name(context: FileContext, node: TSNode) -> str | None:
    """
    Attempt to recover the base identifier name from an expression.

        p                -> "p"
        *p               -> "p"
        (p)              -> "p"
        (void*)p         -> "p"
        p->field         -> "p"
        (*p).field       -> "p"
    """
    if node.type == "identifier":
        return get_source_span(context, node).strip()
    for child in node.children:
        name = _extract_identifier_name(context, child)
        if name:
            return name
    return None


def _is_dereference_of_pointer(context: FileContext, node: TSNode) -> tuple[bool, str | None]:
    """
    Return (True, ptr_name) if node looks like a pointer dereference, else (False, None).
    """
    # tree-sitter-c uses pointer_expression for both *p and p->field (not unary_expression for *p)
    if node.type == "pointer_expression":
        for i in range(node.child_count):
            child = node.child(i)
            if child is not None:
                name = _extract_identifier_name(context, child)
                if name:
                    return True, name

    # Some grammars use unary_expression for *p; keep for compatibility
    if node.type == "unary_expression":
        text = get_source_span(context, node).lstrip()
        if text.startswith("*"):
            name = _extract_identifier_name(context, node)
            if name:
                return True, name

    # p[i]  -> array_subscript_expression (treat as pointer dereference for this rule)
    if node.type == "subscript_expression":
        if node.child_count >= 1:
            base = node.child(0)
            if base is not None:
                name = _extract_identifier_name(context, base)
                if name:
                    return True, name

    return False, None


def _is_descendant(node: TSNode, ancestor: TSNode) -> bool:
    n = node
    while n is not None:
        if n == ancestor:
            return True
        n = n.parent
    return False


def _condition_null_check_kind(
    context: FileContext,
    condition: TSNode,
    ptr_name: str,
) -> str | None:
    """
      - "non_null_then": condition is like ptr != NULL → safe in then-branch
      - "null_then": condition is !ptr or ptr == NULL → safe in else-branch
      - None: not a recognized null check
    """
    # !p  → null_then (then-branch is "p is null", else is non-null)
    for node in _walk(condition):
        if node.type == "unary_expression":
            text = get_source_span(context, node).strip()
            if text.startswith("!"):
                name = _extract_identifier_name(context, node)
                if name == ptr_name:
                    return "null_then"
        if node.type != "binary_expression":
            continue
        text = get_source_span(context, node)
        if ptr_name not in text:
            continue
        if "NULL" not in text and "0" not in text:
            continue
        if "!=" in text:
            return "non_null_then"  # ptr != NULL
        if "==" in text:
            return "null_then"     # ptr == NULL
    return None


def _consequence_returns_or_exits(context: FileContext, if_node: TSNode) -> bool:
    consequence = if_node.child_by_field_name("consequence")
    if consequence is None:
        return False
    for child in consequence.children:
        if child.type == "return":
            return True
    return False


def _is_protected_by_null_check(context: FileContext, deref_node: TSNode, ptr_name: str) -> bool:
    """
    True if the dereference is guarded by a null check.

      - if (ptr != NULL) { ... *ptr ... }  (deref in then-branch)
      - if (!ptr) return; ... *ptr ...    (deref after early-return in same block)
      - if (!ptr) ... ; else { ... *ptr ... }  (deref in else-branch)
      - if (ptr == NULL) return; ... *ptr ...
    """
    parent = deref_node.parent
    while parent is not None:
        if parent.type == "if_statement":
            cond = parent.child_by_field_name("condition")
            if cond is None and parent.child_count >= 2:
                cond = parent.child(1)
            if cond is not None:
                kind = _condition_null_check_kind(context, cond, ptr_name)
                if kind == "non_null_then":
                    consequence = parent.child_by_field_name("consequence")
                    if consequence is not None and _is_descendant(deref_node, consequence):
                        return True
                elif kind == "null_then":
                    alternative = parent.child_by_field_name("alternative")
                    if alternative is not None and _is_descendant(deref_node, alternative):
                        return True
        if parent.type == "compound_statement":
            # Preceding "if (!p) return ..." or "if (p == NULL) return ..." in same block
            children = parent.children
            for i, child in enumerate(children):
                if not _is_descendant(deref_node, child):
                    continue
                for j in range(i):
                    prev = children[j]
                    if prev.type != "if_statement":
                        continue
                    pcond = prev.child_by_field_name("condition")
                    if pcond is None:
                        continue
                    pkind = _condition_null_check_kind(context, pcond, ptr_name)
                    if pkind == "null_then" and _consequence_returns_or_exits(context, prev):
                        return True
                break
        if parent.type in {"function_definition", "translation_unit"}:
            break
        parent = parent.parent
    return False


class NullChecksRule(Rule):
    """Detect pointer dereferences that are not obviously guarded by a NULL check."""

    id = "null-checks"
    name = "Missing NULL check on pointer dereference"

    def run(self, context: Any, config: Any) -> list[Any]:
        findings: list[Finding] = []
        file_ctx: FileContext = context  # for type checkers / clarity
        root = file_ctx.root_node

        for node in _walk(root):
            is_deref, ptr_name = _is_dereference_of_pointer(file_ctx, node)
            if not is_deref or not ptr_name:
                continue

            if _is_protected_by_null_check(file_ctx, node, ptr_name):
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
                        f"Pointer '{ptr_name}' is dereferenced without an obvious "
                        "preceding NULL check; this may lead to a NULL pointer dereference."
                    ),
                    location=location,
                    severity="warning",
                )
            )

        return findings
