# Memory management error detection: detects memory leaks, double free, and missing free

from __future__ import annotations

"""
Memory management error detection: flag missing frees (memory leaks) and double frees.

- We consider allocations: calls to malloc, calloc, or realloc whose result is
  assigned to a variable (e.g. `p = malloc(n)` or `int *p = malloc(n)`).

- We consider frees: calls to free(ptr) and extract the pointer argument's
  root identifier (e.g. free(p) -> "p").

- Allocating functions: we detect functions that return a pointer from
  malloc/calloc/realloc (or from another such allocating function). Calls to
  these functions are treated like malloc when the result is assigned (e.g.
  p = my_alloc() counts as an allocation).

- Freeing functions: we detect functions that call free() on one of their
  parameters. Calls to these functions are treated like free (e.g. my_free(p)
  counts as freeing p).

- Missing free (leak): a variable that receives an allocation (or result of an
  allocating function) in a function but is never passed to free() or a freeing
  function in that function.

- Double free: the same variable is passed to free() more than once in a function;
  we report each free after the first.
"""

from typing import Any, Iterable, Set

from tree_sitter import Node as TSNode

from scanner.context import FileContext, get_line_col, get_source_span
from scanner.findings.models import Finding, Location
from scanner.rules.base import Rule


ALLOC_FUNCS = frozenset({"malloc", "calloc", "realloc"})
FREE_FUNC = "free"


def _walk(node: TSNode) -> Iterable[TSNode]:
    yield node
    for child in node.children:
        yield from _walk(child)


def _get_called_function_name(context: FileContext, call_node: TSNode) -> str | None:
    """Return the bare function name for a call_expression (e.g. 'malloc', 'free'), or None."""
    if call_node.type != "call_expression" or call_node.child_count == 0:
        return None
    func_node = call_node.child(0)
    if func_node is None or func_node.type != "identifier":
        return None
    return get_source_span(context, func_node).strip()


def _extract_root_identifier(context: FileContext, node: TSNode) -> str | None:
    """
    Recursively extract the first (root) identifier name from an expression or
    declarator subtree. Handles: p, *p, (p), (void*)p, p->next, and declarators
    like pointer_declarator -> identifier.
    """
    if node.type == "identifier":
        return get_source_span(context, node).strip()
    for child in node.children:
        name = _extract_root_identifier(context, child)
        if name:
            return name
    return None


def _get_function_name(context: FileContext, func_def: TSNode) -> str | None:
    if func_def.type != "function_definition":
        return None
    decl = func_def.child_by_field_name("declarator")
    if decl is None or decl.type != "function_declarator":
        return None
    name_node = decl.child_by_field_name("declarator")
    if name_node is None:
        return None
    return _extract_root_identifier(context, name_node)


def _get_parameter_names(context: FileContext, func_def: TSNode) -> Set[str]:
    names: Set[str] = set()
    if func_def.type != "function_definition":
        return names
    decl = func_def.child_by_field_name("declarator")
    if decl is None:
        return names
    params = decl.child_by_field_name("parameters")
    if params is None:
        return names
    for child in params.children:
        if child.type == "parameter_declaration":
            param_decl = child.child_by_field_name("declarator")
            if param_decl is not None:
                n = _extract_root_identifier(context, param_decl)
                if n:
                    names.add(n)
    return names


def _skip_parens(node: TSNode) -> TSNode:
    while node.type == "parenthesized_expression" and node.child_count >= 2:
        node = node.child(1)
    return node


def _get_allocated_variable_names(
    context: FileContext,
    body: TSNode,
    alloc_funcs: Set[str],
) -> Set[str]:
    # Return the set of variable names that receive an allocation in this body
    names: Set[str] = set()
    for node in _walk(body):
        if node.type == "assignment_expression":
            pair = _get_alloc_assignment_var(context, node, alloc_funcs)
            if pair:
                names.add(pair[1])
        elif node.type == "init_declarator":
            pair = _get_alloc_init_declarator_var(context, node, alloc_funcs)
            if pair:
                names.add(pair[1])
    return names


def _discover_allocating_functions(context: FileContext, root: TSNode) -> Set[str]:
    # find functions that act like allocators
    func_defs = [n for n in _walk(root) if n.type == "function_definition"]
    allocating: Set[str] = set(ALLOC_FUNCS)
    while True:
        added: Set[str] = set()
        for fd in func_defs:
            name = _get_function_name(context, fd)
            if not name or name in allocating:
                continue
            body = fd.child_by_field_name("body")
            if body is None:
                continue
            allocated_vars = _get_allocated_variable_names(context, body, allocating)
            for node in _walk(body):
                if node.type != "return_statement":
                    continue
                value = node.child_by_field_name("value")
                if value is None:
                    continue
                value = _skip_parens(value)
                if value.type == "call_expression":
                    callee = _get_called_function_name(context, value)
                    if callee in allocating:
                        added.add(name)
                        break
                elif value.type == "identifier":
                    ret_name = get_source_span(context, value).strip()
                    if ret_name in allocated_vars:
                        added.add(name)
                        break
        if not added:
            break
        allocating |= added
    return allocating


def _discover_freeing_functions(context: FileContext, root: TSNode) -> Set[str]:
    # find functions that act like free
    freeing: Set[str] = {FREE_FUNC}
    for node in _walk(root):
        if node.type != "function_definition":
            continue
        name = _get_function_name(context, node)
        if not name:
            continue
        params = _get_parameter_names(context, node)
        if not params:
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue
        for child in _walk(body):
            if child.type != "call_expression":
                continue
            callee = _get_called_function_name(context, child)
            if callee != FREE_FUNC:
                continue
            if child.child_count < 2:
                continue
            args = child.child(1)
            if args is None or args.child_count < 2:
                continue
            first_arg = args.child(1)
            if first_arg is None:
                continue
            ptr_name = _extract_root_identifier(context, first_arg)
            if ptr_name and ptr_name in params:
                freeing.add(name)
                break
    return freeing


def _is_alloc_call(
    context: FileContext,
    node: TSNode,
    alloc_funcs: Set[str],
) -> bool:
    node = _skip_parens(node)
    if node.type != "call_expression":
        return False
    name = _get_called_function_name(context, node)
    return name in alloc_funcs


def _get_alloc_assignment_var(
    context: FileContext,
    node: TSNode,
    alloc_funcs: Set[str],
) -> tuple[TSNode, str] | None:
    if node.type != "assignment_expression":
        return None
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if right is None or not _is_alloc_call(context, right, alloc_funcs):
        return None
    if left is None:
        return None
    var_name = _extract_root_identifier(context, left)
    if not var_name:
        return None
    alloc_node = _skip_parens(right)
    return alloc_node, var_name


def _get_alloc_init_declarator_var(
    context: FileContext,
    init_declarator: TSNode,
    alloc_funcs: Set[str],
) -> tuple[TSNode, str] | None:
    """
    If init_declarator has an initializer that is a call to an allocating function,
    return (alloc_call_node, var_name). Otherwise None.
    """
    if init_declarator.type != "init_declarator":
        return None
    declarator = init_declarator.child_by_field_name("declarator")
    value = init_declarator.child_by_field_name("value")
    if value is None:
        value = init_declarator.child_by_field_name("initializer")
    if declarator is None or value is None:
        return None
    alloc_node = _skip_parens(value)
    if not _is_alloc_call(context, alloc_node, alloc_funcs):
        return None
    var_name = _extract_root_identifier(context, declarator)
    if not var_name:
        return None
    return alloc_node, var_name


def _collect_allocations_and_frees(
    context: FileContext,
    body: TSNode,
    alloc_funcs: Set[str],
    free_funcs: Set[str],
) -> tuple[list[tuple[TSNode, str]], list[tuple[TSNode, str]]]:
    allocations: list[tuple[TSNode, str]] = []
    frees: list[tuple[TSNode, str]] = []

    for node in _walk(body):
        if node.type == "call_expression":
            name = _get_called_function_name(context, node)
            if name in free_funcs and node.child_count >= 2:
                args = node.child(1)
                if args and args.child_count >= 2:
                    first_arg = args.child(1)
                    if first_arg:
                        ptr_name = _extract_root_identifier(context, first_arg)
                        if ptr_name:
                            frees.append((node, ptr_name))
            continue

        if node.type == "assignment_expression":
            pair = _get_alloc_assignment_var(context, node, alloc_funcs)
            if pair:
                allocations.append(pair)
            continue

        if node.type == "init_declarator":
            pair = _get_alloc_init_declarator_var(context, node, alloc_funcs)
            if pair:
                allocations.append(pair)
            continue

    return allocations, frees


def _find_double_frees(
    frees: list[tuple[TSNode, str]],
) -> list[tuple[TSNode, str]]:
    """Return list of (free_node, var_name) for each free that is a second+ free of the same var."""
    seen: set[str] = set()
    double_free_nodes: list[tuple[TSNode, str]] = []
    for node, var_name in frees:
        if var_name in seen:
            double_free_nodes.append((node, var_name))
        else:
            seen.add(var_name)
    return double_free_nodes


def _find_missing_frees(
    allocations: list[tuple[TSNode, str]],
    frees: list[tuple[TSNode, str]],
) -> list[tuple[TSNode, str]]:
    """Return list of (alloc_node, var_name) for allocations never freed in this scope."""
    freed_vars = {var_name for _, var_name in frees}
    return [(node, var_name) for node, var_name in allocations if var_name not in freed_vars]


class MemoryManagementRule(Rule):
    # Detect memory management errors: missing frees (leaks) and double frees

    id = "memory-management"
    name = "Memory management error (missing free or double free)"

    def run(self, context: Any, config: Any) -> list[Any]:
        findings: list[Finding] = []
        file_ctx: FileContext = context
        root = file_ctx.root_node

        alloc_funcs = _discover_allocating_functions(file_ctx, root)
        free_funcs = _discover_freeing_functions(file_ctx, root)

        for node in _walk(root):
            if node.type != "function_definition":
                continue
            body = node.child_by_field_name("body")
            if body is None or body.type != "compound_statement":
                continue

            allocations, frees = _collect_allocations_and_frees(
                file_ctx, body, alloc_funcs, free_funcs
            )

            for free_node, var_name in _find_double_frees(frees):
                line, col = get_line_col(free_node)
                findings.append(
                    Finding(
                        rule_id=self.id,
                        message=(
                            f"Double free: '{var_name}' may be freed more than once; "
                            "this is undefined behavior."
                        ),
                        location=Location(
                            path=file_ctx.path,
                            line=line,
                            column=col,
                            snippet=get_source_span(file_ctx, free_node),
                        ),
                        severity="warning",
                    )
                )

            for alloc_node, var_name in _find_missing_frees(allocations, frees):
                line, col = get_line_col(alloc_node)
                findings.append(
                    Finding(
                        rule_id=self.id,
                        message=(
                            f"Possible memory leak: '{var_name}' is allocated but never freed "
                            "in this function."
                        ),
                        location=Location(
                            path=file_ctx.path,
                            line=line,
                            column=col,
                            snippet=get_source_span(file_ctx, alloc_node),
                        ),
                        severity="warning",
                    )
                )

        return findings
