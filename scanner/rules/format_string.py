# Format string vulnerability detection: detects unsafe printf-style functions with user input

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from scanner.findings.models import Finding, Location
from scanner.rules.base import Rule

# --- helpers ---------------------------------------------------------------


def _node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _line_col(node: Any) -> Tuple[int, int]:
    row, col = node.start_point
    return row + 1, col + 1


def _walk(node: Any):
    yield node
    for child in node.children:
        yield from _walk(child)


def _get_call_name(call_node: Any, source: bytes) -> Optional[str]:
    fn = call_node.child_by_field_name("function")
    if fn is None:
        return None

    if fn.type == "identifier":
        return _node_text(source, fn)

    if fn.type == "field_expression":
        field = fn.child_by_field_name("field")
        if field is not None and field.type == "identifier":
            return _node_text(source, field)

    return _node_text(source, fn)


def _get_call_args(call_node: Any) -> List[Any]:
    args = call_node.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.children if getattr(c, "is_named", False)]


_STRING_ESCAPE_RE = re.compile(r"\\(.)")


def _unquote_c_string_literal(raw: str) -> Optional[str]:
    raw = raw.strip()
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return None
    body = raw[1:-1]

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


def _is_string_literal_node(node: Any) -> bool:
    return node is not None and node.type == "string_literal"


def _looks_nonliteral_format(fmt_node: Any) -> bool:
    # If it’s not a literal string, it may be attacker-controlled.
    # This is conservative: identifiers, call_expression, conditional_expression, etc.
    return fmt_node is not None and fmt_node.type != "string_literal"


# Regex for printf-style conversions (rough but practical)
# - skips %%
# - captures conversion specifier at end (s, d, x, n, etc.)
_PRINTF_CONV_RE = re.compile(
    r"%(?:[-+ #0]*)"  # flags
    r"(?:\d+|\*)?"  # width
    r"(?:\.(?:\d+|\*))?"  # precision
    r"(?:hh|h|ll|l|j|z|t|L)?"  # length
    r"([diuoxXfFeEgGaAcspn%])"
)

# Regex for scanf-style conversions (very rough)
_SCANF_CONV_RE = re.compile(
    r"%(?:\*?)"  # assignment suppression
    r"(?:\d+)?"  # width (digits only)
    r"(?:hh|h|ll|l|j|z|t|L)?"  # length
    r"(\[[^\]]+\]|[diuoxXfFeEgGaAcspn%])"
)


def _printf_conversions(fmt: str) -> List[str]:
    convs = []
    i = 0
    while i < len(fmt):
        if fmt[i] == "%" and i + 1 < len(fmt) and fmt[i + 1] == "%":
            i += 2
            continue
        m = _PRINTF_CONV_RE.match(fmt, i)
        if m:
            spec = m.group(1)
            if spec != "%":
                convs.append(spec)
            i = m.end()
        else:
            i += 1
    return convs


def _scanf_has_unbounded_string(fmt: str) -> bool:
    # Look for %s or %[... with no width digits
    # This is conservative.
    s = fmt.replace("%%", "")
    # Find occurrences of %s or %[...]
    # If it’s %s with no digits after %, it’s unbounded.
    for m in re.finditer(r"%(?:\*?)((?:\d+)?)(?:hh|h|ll|l|j|z|t|L)?(s|\[)", s):
        width = m.group(1)
        kind = m.group(2)
        if kind in ("s", "[") and width == "":
            return True
    return False


@dataclass(frozen=True)
class _Issue:
    message: str
    severity: str  # "low" | "medium" | "high"


# --- rule ------------------------------------------------------------------


class FormatStringRule(Rule):
    id = "format-string"
    name = "Format string risk"

    # printf-like sinks: first arg is format (unless fprintf/snprintf/etc.)
    _PRINTF_LIKE = {
        "printf",
        "vprintf",
        "sprintf",
        "vsprintf",
        "snprintf",
        "vsnprintf",
        "syslog",
        "vsyslog",
    }

    # fprintf-like: (stream, fmt, ...)
    _FPRINTF_LIKE = {
        "fprintf",
        "vfprintf",
        "dprintf",
        "vdprintf",
    }

    # scanf-like: format handling, can also have format string attacks / %n, etc.
    _SCANF_LIKE = {
        "scanf",
        "fscanf",
        "sscanf",
        "vscanf",
        "vfscanf",
        "vsscanf",
    }

    def run(self, context: Any, config: Any) -> List[Finding]:
        tree = getattr(context, "tree", None)
        source: bytes = getattr(context, "source", b"")
        path = getattr(context, "path", None)

        if tree is None or path is None:
            return []

        findings: List[Finding] = []

        for node in _walk(tree.root_node):
            if node.type != "call_expression":
                continue

            fn = _get_call_name(node, source)
            if not fn:
                continue

            args = _get_call_args(node)
            issue = self._analyze_call(fn, node, args, source)
            if issue is None:
                continue

            line, col = _line_col(node)
            findings.append(
                Finding(
                    rule_id=self.id,
                    message=issue.message,
                    location=Location(
                        path=path,
                        line=line,
                        column=col,
                        snippet=_node_text(source, node).strip(),
                    ),
                    severity=issue.severity,
                )
            )

        return findings

    def _analyze_call(
        self,
        fn: str,
        call_node: Any,
        args: List[Any],
        source: bytes,
    ) -> Optional[_Issue]:
        # Identify which arg is the format string
        fmt_index: Optional[int] = None

        if fn in self._PRINTF_LIKE:
            # printf(fmt, ...)
            # snprintf(dst, n, fmt, ...)
            if fn in {"snprintf", "vsnprintf"}:
                fmt_index = 2 if len(args) >= 3 else None
            else:
                fmt_index = 0 if len(args) >= 1 else None

        elif fn in self._FPRINTF_LIKE:
            # fprintf(stream, fmt, ...)
            fmt_index = 1 if len(args) >= 2 else None

        elif fn in self._SCANF_LIKE:
            # scanf(fmt, ...)
            # fscanf(stream, fmt, ...)
            # sscanf(str, fmt, ...)
            fmt_index = (
                0 if fn in {"scanf", "vscanf"} else 1 if len(args) >= 2 else None
            )

        else:
            return None

        if fmt_index is None or len(args) <= fmt_index:
            return None

        fmt_node = args[fmt_index]
        fmt_raw = _node_text(source, fmt_node)
        fmt_lit = (
            _unquote_c_string_literal(fmt_raw)
            if _is_string_literal_node(fmt_node)
            else None
        )

        # 1) Non-literal format string → classic format-string vulnerability
        # Examples: printf(user); syslog(msg); fprintf(fp, buf);
        if _looks_nonliteral_format(fmt_node):
            # Strongest when function is printf-family; for scanf-family it’s still dangerous but slightly different.
            return _Issue(
                message=f"Potential format string vulnerability: '{fn}' called with non-literal format string.",
                severity="high",
            )

        # If it’s a literal format string, we can do deeper checks.
        if fmt_lit is None:
            return None

        # 2) %n is dangerous (writes to memory)
        if "%n" in fmt_lit:
            # Could be false positive in "%%n" etc, but rare and still worth review.
            return _Issue(
                message=f"Dangerous '%n' in {fn} format string (writes to memory). Avoid unless strictly necessary and safe.",
                severity="high",
            )

        # 3) Optional: scanf-family unbounded %s / %[...]
        if fn in self._SCANF_LIKE and _scanf_has_unbounded_string(fmt_lit):
            return _Issue(
                message=f"Potential overflow: '{fn}' format contains %s/%[...] without a width limit.",
                severity="high",
            )

        # 4) Lightweight mismatch check for printf-family:
        # Count conversions and compare to number of provided args after the format.
        if fn in (self._PRINTF_LIKE | self._FPRINTF_LIKE):
            convs = _printf_conversions(fmt_lit)
            expected = len(convs)

            provided = len(args) - (fmt_index + 1)

            # If there are '*' widths/precisions, our conversion count may undercount required args.
            # We’ll still flag only the obvious "too few args for conversions" case.
            if provided < expected:
                return _Issue(
                    message=f"Possible format/argument mismatch in '{fn}': format expects ~{expected} arg(s), but {provided} provided.",
                    severity="medium",
                )

        return None
