# Buffer overflow risk detection: detects array bounds violations and unsafe buffer operations

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from scanner.findings.models import Finding, Location
from scanner.rules.base import Rule

# --- helpers ---------------------------------------------------------------


def _node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _line_col(node: Any) -> Tuple[int, int]:
    # Tree-sitter points are 0-based (row, column)
    row, col = node.start_point
    return row + 1, col + 1


def _walk(node: Any):
    yield node
    for child in node.children:
        yield from _walk(child)


def _get_call_name(call_node: Any, source: bytes) -> Optional[str]:
    """
    Tree-sitter-c call_expression generally looks like:
      (call_expression
         function: (identifier) or (field_expression ...)
         arguments: (argument_list ...))

    We return a best-effort function name string.
    """
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return None

    # simplest: identifier
    if fn.type == "identifier":
        return _node_text(source, fn)

    # e.g., foo->bar(...) or foo.bar(...)
    # field_expression typically has a 'field' identifier
    if fn.type == "field_expression":
        field = fn.child_by_field_name("field")
        if field is not None and field.type == "identifier":
            return _node_text(source, field)

    # fallback: raw text
    return _node_text(source, fn)


def _get_call_args(call_node: Any) -> List[Any]:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    # argument_list children includes punctuation; filter to named nodes
    return [c for c in args.children if getattr(c, "is_named", False)]


def _parse_int_literal(node: Any, source: bytes) -> Optional[int]:
    if node is None:
        return None
    if node.type != "number_literal":
        return None
    txt = _node_text(source, node).lower().replace("_", "")
    try:
        if txt.startswith("0x"):
            return int(txt, 16)
        if txt.startswith("0b"):
            return int(txt, 2)
        if txt.startswith("0") and txt != "0":
            # octal (C-style), best-effort
            return int(txt, 8)
        return int(txt, 10)
    except ValueError:
        return None


_STRING_ESCAPE_RE = re.compile(r"\\(.)")


def _unquote_c_string_literal(raw: str) -> Optional[str]:
    """
    raw includes quotes for a single string literal node, e.g. "abc\n"
    Tree-sitter-c often returns tokens including quotes.
    Returns decoded-ish string (best effort) or None if not a simple literal.
    """
    raw = raw.strip()
    if len(raw) < 2:
        return None
    if raw[0] != '"' or raw[-1] != '"':
        return None
    body = raw[1:-1]

    # best-effort unescape (not a full C lexer)
    def repl(m):
        ch = m.group(1)
        return {
            "n": "\n",
            "t": "\t",
            "r": "\r",
            "\\": "\\",
            '"': '"',
            "0": "\0",
        }.get(ch, ch)

    return _STRING_ESCAPE_RE.sub(repl, body)


def _format_string_has_unbounded_s(fmt: str) -> bool:
    """
    Flag risky patterns like %s without a width:
      "%s"
      "%10s" is fine
    Also flags %[... ] without width (very rough).
    """
    # Remove escaped %% so they don't confuse scanning
    s = fmt.replace("%%", "")

    # Find %... conversions
    # This is intentionally conservative (false positives > false negatives).
    conv = re.finditer(
        r"%(?:[-+ #0]*)?(?:\d+|\*)?(?:\.\d+|\.\*)?(?:hh|h|ll|l|j|z|t|L)?([a-zA-Z\[])", s
    )
    for m in conv:
        spec = m.group(0)
        kind = m.group(1)

        # %s: require a width like %32s or %*s
        if kind == "s":
            # does spec contain an explicit width before optional precision?
            # simplest: look for % then flags then digits/* (width)
            # our regex already includes width group, but easiest is check presence:
            after_percent = spec[1:]
            # strip flags
            after_percent = re.sub(r"^[-+ #0]*", "", after_percent)
            has_width = bool(re.match(r"(\d+|\*)", after_percent))
            if not has_width:
                return True

        # %[...]: scanset — also needs width to avoid overflow: "%15[^\n]"
        if kind == "[":
            after_percent = spec[1:]
            after_percent = re.sub(r"^[-+ #0]*", "", after_percent)
            has_width = bool(re.match(r"(\d+|\*)", after_percent))
            if not has_width:
                return True

    return False


# --- rule ------------------------------------------------------------------


@dataclass(frozen=True)
class _Issue:
    message: str
    severity: str  # "low" | "medium" | "high"


class BufferOverflowRule(Rule):
    id = "buffer-overflow"
    name = "Buffer overflow risk"

    # APIs that are essentially always dangerous
    _BANNED = {
        "gets",  # removed from C11 for a reason
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
    }

    # APIs that can be dangerous depending on arguments
    _WATCH = {
        "scanf",
        "fscanf",
        "sscanf",
        "vscanf",
        "vfscanf",
        "vsscanf",
        "memcpy",
        "memmove",
        # strncpy/strncat are bounded - only flag if clearly wrong (handled in _analyze_call)
    }

    def run(self, context: Any, config: Any) -> List[Finding]:
        tree = getattr(context, "tree", None)
        source: bytes = getattr(context, "source", b"")
        path = getattr(context, "path", None)

        if tree is None or path is None:
            return []

        self._current_path = path  # for OOB helpers

        # Build a very small map of local fixed-size arrays:
        #   char buf[16];  => sizes["buf"] = 16
        sizes = self._collect_fixed_array_sizes(tree.root_node, source)

        findings: List[Finding] = []

        # Check for out-of-bounds array writes (direct subscript, loop bounds)
        for node in _walk(tree.root_node):
            if node.type == "assignment_expression":
                ob = self._check_direct_oob_write(node, source, sizes)
                if ob is not None:
                    findings.append(ob)
            elif node.type == "for_statement":
                for ob in self._check_loop_oob(node, source, sizes):
                    findings.append(ob)

        for node in _walk(tree.root_node):
            if node.type != "call_expression":
                continue

            fn_name = _get_call_name(node, source)
            if not fn_name:
                continue

            args = _get_call_args(node)

            issue = self._analyze_call(fn_name, node, args, source, sizes)
            if issue is None:
                continue

            line, col = _line_col(node)
            snippet = _node_text(source, node)

            findings.append(
                Finding(
                    rule_id=self.id,
                    message=issue.message,
                    location=Location(
                        path=path,
                        line=line,
                        column=col,
                        snippet=snippet.strip(),
                    ),
                    severity=issue.severity,
                )
            )

        return findings

    def _analyze_call(
        self,
        fn_name: str,
        call_node: Any,
        args: List[Any],
        source: bytes,
        sizes: Dict[str, int],
    ) -> Optional[_Issue]:
        # 1) Hard banned calls
        if fn_name in self._BANNED:
            return _Issue(
                message=f"Use of unsafe function '{fn_name}' can cause buffer overflow. Prefer bounded alternatives.",
                severity="high",
            )

        # 2) scanf-family: flag unbounded %s / %[...]
        if fn_name in {"scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf"}:
            # format string position differs:
            # scanf(fmt, ...)
            # fscanf(stream, fmt, ...)
            # sscanf(str, fmt, ...)
            fmt_arg_index = 0 if fn_name in {"scanf", "vscanf"} else 1
            if len(args) > fmt_arg_index:
                fmt_raw = _node_text(source, args[fmt_arg_index])
                fmt = _unquote_c_string_literal(fmt_raw)
                if fmt is not None and _format_string_has_unbounded_s(fmt):
                    return _Issue(
                        message=f"Potential overflow: '{fn_name}' format string contains %s/%[...] without a width.",
                        severity="high",
                    )
                # If not a literal, still warn (lower severity)
                if fmt is None:
                    return _Issue(
                        message=f"Review '{fn_name}': non-literal format string may contain unbounded %s conversions.",
                        severity="medium",
                    )

        # 3) memcpy/memmove: if we can infer dest buffer size and length literal exceeds it
        if fn_name in {"memcpy", "memmove"} and len(args) >= 3:
            dest = args[0]
            n = args[2]

            dest_name = _identifier_name(dest, source)
            n_val = _parse_int_literal(n, source)

            if dest_name and n_val is not None and dest_name in sizes:
                if n_val > sizes[dest_name]:
                    return _Issue(
                        message=f"Definite overflow: {fn_name} writes {n_val} bytes into '{dest_name}[{sizes[dest_name]}]'.",
                        severity="high",
                    )
                # still risky if it’s close / equal? (optional)
                if n_val == sizes[dest_name]:
                    return _Issue(
                        message=f"Risky: {fn_name} writes {n_val} bytes into '{dest_name}[{sizes[dest_name]}]' (no room for terminator if string data).",
                        severity="medium",
                    )
            else:
                return _Issue(
                    message=f"Review '{fn_name}': ensure copy length does not exceed destination buffer.",
                    severity="medium",
                )

        return None

    def _collect_fixed_array_sizes(self, root: Any, source: bytes) -> Dict[str, int]:
        """
        Very small local inference:
          char buf[16];
        We’ll map buf -> 16 when size is a literal.
        """
        sizes: Dict[str, int] = {}

        for node in _walk(root):
            if node.type != "declaration":
                continue

            # declaration contains one or more init_declarator / declarator nodes.
            for child in node.children:
                if not getattr(child, "is_named", False):
                    continue
                # Most relevant types: init_declarator, declarator
                # We search inside for array_declarator
                for sub in _walk(child):
                    if sub.type != "array_declarator":
                        continue

                    # array_declarator typically has:
                    #  declarator: (identifier) or (pointer_declarator ...)
                    #  size: (number_literal) or expression
                    decl = sub.child_by_field_name("declarator")
                    size_node = sub.child_by_field_name("size")
                    if decl is None or size_node is None:
                        continue

                    name = _identifier_name(decl, source)
                    size_val = _parse_int_literal(size_node, source)
                    if name and size_val is not None:
                        sizes[name] = size_val

        return sizes

    def _check_direct_oob_write(
        self, assign_node: Any, source: bytes, sizes: Dict[str, int]
    ) -> Optional[Finding]:
        """
        Check assignment_expression like arr[4] = 42.
        Left side must be subscript_expression with constant index.
        """
        left = assign_node.child_by_field_name("left")
        if left is None or left.type != "subscript_expression":
            return None
        arr_node = left.child_by_field_name("argument")
        index_node = left.child_by_field_name("index")
        if index_node is None or index_node.type != "number_literal":
            return None
        arr_name = _identifier_name(arr_node, source)
        index_val = _parse_int_literal(index_node, source)
        if arr_name is None or index_val is None or arr_name not in sizes:
            return None
        arr_size = sizes[arr_name]
        if index_val >= arr_size:
            line, col = _line_col(assign_node)
            path = getattr(self, "_current_path", None)
            if path is None:
                return None
            return Finding(
                rule_id=self.id,
                message=f"Out-of-bounds write: '{arr_name}[{index_val}]' exceeds array size {arr_size}.",
                location=Location(
                    path=self._current_path,
                    line=line,
                    column=col,
                    snippet=_node_text(source, assign_node).strip(),
                ),
                severity="high",
            )
        return None

    def _check_loop_oob(
        self, for_node: Any, source: bytes, sizes: Dict[str, int]
    ) -> List[Finding]:
        """
        Check for_statement: for (i=0; i<=8; i++) buf[i]='A' with buf[8].
        Extract loop var, max index from condition, find array writes in body.
        """
        findings: List[Finding] = []
        path = getattr(self, "_current_path", None)
        if path is None:
            return findings
        # for_statement: for ( init ; condition ; update ) body
        init = for_node.child_by_field_name("initializer")
        cond = for_node.child_by_field_name("condition")
        body = for_node.child_by_field_name("body")
        if init is None and for_node.child_count >= 3:
            init = for_node.child(2)
        if cond is None and for_node.child_count >= 5:
            cond = for_node.child(4)
        if body is None and for_node.child_count >= 9:
            body = for_node.child(8)
        if init is None or cond is None or body is None:
            return findings
        # init: i = 0 -> assignment_expression
        loop_var = None
        if init.type == "assignment_expression":
            left = init.child_by_field_name("left")
            if left and left.type == "identifier":
                loop_var = _node_text(source, left)
        if not loop_var:
            return findings
        # condition: i <= 8 or i < 9 -> binary_expression
        max_index: Optional[int] = None
        if cond.type == "binary_expression":
            op_node = cond.child_by_field_name("operator")
            op = _node_text(source, op_node) if op_node else ""
            right = cond.child_by_field_name("right")
            if right and right.type == "number_literal":
                bound = _parse_int_literal(right, source)
                if bound is not None:
                    if op in ("<=", "=="):
                        max_index = bound
                    elif op == "<":
                        max_index = bound - 1 if bound > 0 else None
        if max_index is None:
            return findings
        # Walk body for arr[loop_var] = ... or arr[loop_var]
        for sub in _walk(body):
            if sub.type != "assignment_expression":
                continue
            left = sub.child_by_field_name("left")
            if left is None or left.type != "subscript_expression":
                continue
            arg = left.child_by_field_name("argument") or (
                left.children[0] if left.children else None
            )
            idx = left.child_by_field_name("index") or (
                left.children[2] if len(left.children) >= 3 else None
            )
            if arg is None or idx is None:
                continue
            arr_name = _identifier_name(arg, source)
            if arr_name is None or arr_name not in sizes:
                continue
            if idx.type == "identifier" and _node_text(source, idx) == loop_var:
                if max_index >= sizes[arr_name]:
                    line, col = _line_col(sub)
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            message=f"Out-of-bounds loop: index '{loop_var}' reaches {max_index}, but '{arr_name}' has size {sizes[arr_name]}.",
                            location=Location(
                                path=path,
                                line=line,
                                column=col,
                                snippet=_node_text(source, sub).strip(),
                            ),
                            severity="high",
                        )
                    )
                    break
        return findings


def _identifier_name(node: Any, source: bytes) -> Optional[str]:
    """
    Best-effort to get identifier from:
      identifier
      parenthesized_expression(identifier)
      pointer_expression(identifier)
      subscript_expression(identifier, ...)
    etc.
    """
    if node.type == "identifier":
        return _node_text(source, node)

    # sometimes declarator field nests identifiers
    for sub in _walk(node):
        if sub.type == "identifier":
            return _node_text(source, sub)

    return None
