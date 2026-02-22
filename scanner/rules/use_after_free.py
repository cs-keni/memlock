# Use-after-free detection: basic heuristic detection of freed pointer usage

from __future__ import annotations

from typing import Any

from tree_sitter import Node as TSNode

from scanner.context import FileContext, get_line_col, get_source_span
from scanner.findings.models import Finding, Location
from scanner.rules.base import Rule


def _walk(node: TSNode):
    """Yield every descendant of node in document order (DFS)."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _get_called_function_name(context: FileContext, call_node: TSNode) -> str | None:
    """Return the bare function name for a call_expression (e.g. 'free'), or None."""
    if call_node.type != "call_expression" or call_node.child_count == 0:
        return None
    func_node = call_node.child(0)
    if func_node is None or func_node.type != "identifier":
        return None
    return get_source_span(context, func_node).strip()


def _extract_pointer_identifier(context: FileContext, node: TSNode) -> str | None:
    """
    From a free() argument node, extract the root identifier name.
    Handles: p, *p, (p), (void*)p, p->next, etc.
    """
    if node.type == "identifier":
        return get_source_span(context, node).strip()
    for child in node.children:
        name = _extract_pointer_identifier(context, child)
        if name:
            return name
    return None


def _enclosing_function(node: TSNode) -> TSNode | None:
    """Return the function_definition that contains this node, or None if at file scope."""
    n = node
    while n:
        if n.type == "function_definition":
            return n
        n = n.parent
    return None


def _is_safe_null_assignment(context: FileContext, ident_node: TSNode) -> bool:
    """
    Return True if this identifier is the LHS of `p = NULL` or `p = 0`.
    That idiom is the recommended way to nullify a freed pointer.
    """
    parent = ident_node.parent
    if parent is None or parent.type != "assignment_expression":
        return False
    if parent.child_count < 3:
        return False
    # LHS is child 0; we must be the LHS (or a direct child of it for *p etc)
    lhs = parent.child(0)
    if lhs is None:
        return False
    # Check we're the LHS identifier (handle *p -> pointer_expr -> identifier)
    if ident_node != lhs and ident_node.parent != lhs:
        # Walk up: ident might be inside init_declarator for "type *p = 0"
        if lhs.start_byte <= ident_node.start_byte <= lhs.end_byte:
            pass  # ident is within LHS
        else:
            return False
    rhs = parent.child(2)
    if rhs is None:
        return False
    rhs_src = get_source_span(context, rhs).strip().upper()
    return rhs.type == "null" or rhs_src in ("NULL", "0", "0L", "0LL")


def _find_uaf_pairs(context: FileContext, root: TSNode) -> list[tuple[TSNode, str]]:
    """
    Find identifier nodes that are used after a free() of the same name in the same function.
    Returns list of (identifier_node, ptr_name) for each use-after-free.
    Skips the safe idiom `p = NULL` after free.
    """
    # Build list of (byte_pos, "free"|"ident", ptr_or_ident_name, node_ref, func_node)
    events: list[tuple[int, str, str, TSNode, TSNode | None]] = []
    for node in _walk(root):
        func = _enclosing_function(node)
        if node.type == "call_expression":
            name = _get_called_function_name(context, node)
            if name == "free" and node.child_count >= 2:
                args = node.child(1)
                if args and args.child_count >= 2:
                    first_arg = args.child(1)
                    if first_arg:
                        ptr_name = _extract_pointer_identifier(context, first_arg)
                        if ptr_name:
                            events.append((node.end_byte, "free", ptr_name, node, func))
        elif node.type == "identifier":
            name = get_source_span(context, node).strip()
            if name and name != "free":  # exclude the "free" in free()
                events.append((node.start_byte, "ident", name, node, func))

    uaf: list[tuple[TSNode, str]] = []
    for i, (pos, kind, name, node, func) in enumerate(events):
        if kind != "ident":
            continue
        if _is_safe_null_assignment(context, node):
            continue
        for j in range(i):
            if events[j][1] != "free":
                continue
            free_end, _, ptr_name, _, free_func = events[j]
            if ptr_name != name or pos <= free_end:
                continue
            # Same function scope: free and use must be in same function
            if func is not None and free_func is not None and func != free_func:
                continue
            uaf.append((node, ptr_name))
            break
    return uaf


class UseAfterFreeRule(Rule):
    """Basic heuristic: flag use of an identifier after a free() of the same name in the same scope."""

    id = "use-after-free"
    name = "Use after free"

    def run(self, context: Any, config: Any) -> list[Any]:
        findings: list[Finding] = []
        root = context.root_node
        uaf_pairs = _find_uaf_pairs(context, root)
        for ident_node, ptr_name in uaf_pairs:
            line, col = get_line_col(ident_node)
            location = Location(
                path=context.path,
                line=line,
                column=col,
                snippet=get_source_span(context, ident_node),
            )
            findings.append(
                Finding(
                    rule_id=self.id,
                    message=f"Possible use-after-free: '{ptr_name}' may be used after free().",
                    location=location,
                    severity="warning",
                )
            )
        return findings
