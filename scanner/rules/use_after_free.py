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


def _find_uaf_pairs(context: FileContext, root: TSNode) -> list[tuple[TSNode, str]]:
    """
    Find identifier nodes that are used after a free() of the same name (same scope).
    Returns list of (identifier_node, ptr_name) for each use-after-free.
    """
    # Build list of (byte_pos, "free"|"ident", ptr_or_ident_name, node_ref)
    events: list[tuple[int, str, str, TSNode]] = []
    for node in _walk(root):
        if node.type == "call_expression":
            name = _get_called_function_name(context, node)
            if name == "free" and node.child_count >= 2:
                args = node.child(1)
                if args and args.child_count >= 2:
                    first_arg = args.child(1)
                    if first_arg:
                        ptr_name = _extract_pointer_identifier(context, first_arg)
                        if ptr_name:
                            events.append((node.end_byte, "free", ptr_name, node))
        elif node.type == "identifier":
            events.append((node.start_byte, "ident", get_source_span(context, node).strip(), node))

    uaf: list[tuple[TSNode, str]] = []
    for i, (pos, kind, name, node) in enumerate(events):
        if kind != "ident":
            continue
        for j in range(i):
            if events[j][1] != "free":
                continue
            free_end, _, ptr_name, _ = events[j]
            if ptr_name == name and pos > free_end:
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
