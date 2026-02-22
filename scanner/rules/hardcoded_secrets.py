# Hardcoded secrets detection: detects passwords, API keys, and tokens in source code

from __future__ import annotations

from typing import Any

from scanner.findings.models import Finding
from scanner.rules.base import Rule


class HardcodedSecretsRule(Rule):
    """
    Detects hardcoded secrets: passwords, API keys, tokens in string literals.
    TODO: Implement - see project-idea.md for AST targets and strategy.
    """

    id = "hardcoded-secrets"
    name = "Hardcoded secrets"

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


_STRING_ESCAPE_RE = re.compile(r'\\(.)')


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


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    n = len(s)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def _is_identifier(node: Any) -> bool:
    return node is not None and node.type == "identifier"


def _first_identifier_text(node: Any, source: bytes) -> Optional[str]:
    # best-effort: find the first identifier in this subtree
    if node is None:
        return None
    if _is_identifier(node):
        return _node_text(source, node)
    for sub in _walk(node):
        if _is_identifier(sub):
            return _node_text(source, sub)
    return None


# --- patterns --------------------------------------------------------------

# suspicious variable names / fields (case-insensitive)
_NAME_HINTS = re.compile(
    r"(?:"
    r"pass(word)?|pwd|secret|token|api[_-]?key|apikey|auth|bearer|"
    r"private[_-]?key|ssh[_-]?key|access[_-]?key|client[_-]?secret|"
    r"session|cookie|jwt|signature|signing|encryption|decrypt|encrypt|"
    r"db[_-]?pass|db[_-]?password|conn(string)?|dsn"
    r")",
    re.IGNORECASE,
)

# obvious inline key/value in strings
_INLINE_KV = re.compile(
    r"(?:"
    r"(pass(word)?|pwd|secret|token|api[_-]?key|apikey|auth|bearer)"
    r")\s*[:=]\s*([^\s\"']{4,})",
    re.IGNORECASE,
)

# token-like shapes
_HEX_LONG = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_BASE64ISH = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# common cloud/provider prefixes (best-effort)
_AWS_AKIA = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GCP_APIKEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")

# PEM blocks in C strings (can happen in embedded certs/keys)
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]+-----")


@dataclass(frozen=True)
class _Issue:
    message: str
    severity: str  # "low" | "medium" | "high"


class HardcodedSecretsRule(Rule):
    id = "hardcoded-secrets"
    name = "Hardcoded secrets"

    def run(self, context: Any, config: Any) -> List[Dict[str, Any]]:
        tree = getattr(context, "tree", None)
        source: bytes = getattr(context, "source", b"")
        path = getattr(context, "path", "<unknown>")

        if tree is None:
            return []

        findings: List[Dict[str, Any]] = []

        # Collect all string_literal nodes and evaluate in context
        for node in _walk(tree.root_node):
            if node.type != "string_literal":
                continue

            raw = _node_text(source, node)
            s = _unquote_c_string_literal(raw)
            if s is None:
                continue

            issue = self._analyze_string_literal(node, s, source)
            if issue is None:
                continue

            line, col = _line_col(node)
            findings.append(
                {
                    "rule_id": self.id,
                    "rule_name": self.name,
                    "severity": issue.severity,
                    "message": issue.message,
                    "path": str(path),
                    "line": line,
                    "column": col,
                    "snippet": raw.strip(),
                }
            )

        return findings

    def _analyze_string_literal(self, node: Any, s: str, source: bytes) -> Optional[_Issue]:
        # Ignore very short strings
        if len(s) < 8:
            return None

        # 1) PEM blocks in string literals (private keys/certs)
        if _PEM_BEGIN.search(s):
            return _Issue(
                message="Embedded PEM material found in string literal (possible certificate/private key). Avoid hardcoding secrets in source.",
                severity="high",
            )

        # 2) JWT
        if _JWT.search(s):
            return _Issue(
                message="JWT-like token found in string literal. Treat as secret and remove from source.",
                severity="high",
            )

        # 3) Provider-ish keys
        if _AWS_AKIA.search(s) or _GCP_APIKEY.search(s):
            return _Issue(
                message="Cloud API key pattern found in string literal. Remove and rotate the credential.",
                severity="high",
            )

        # 4) Inline key/value indicators (password=..., api_key:..., Bearer ...)
        if _INLINE_KV.search(s) or "bearer " in s.lower():
            return _Issue(
                message="Possible credential in string literal (keyword + value). Move to secret manager / env var and rotate if real.",
                severity="high",
            )

        # 5) Long hex/base64-ish with entropy (looks like a token)
        # Use entropy threshold to avoid flagging normal long strings.
        ent = _shannon_entropy(s)
        looks_tokenish = bool(_HEX_LONG.search(s) or _BASE64ISH.search(s))
        if looks_tokenish and ent >= 3.5:
            # higher entropy + long token-ish string -> likely secret
            return _Issue(
                message="High-entropy token-like string found (possible secret). Remove from source and rotate if applicable.",
                severity="high",
            )

        # 6) Contextual: assigned to suspicious variable names (password/token/secret/etc.)
        # Check parent contexts: init_declarator or assignment_expression
        parent = getattr(node, "parent", None)
        if parent is not None:
            # declaration initializer:  char *password = "..."
            if parent.type in {"init_declarator", "initializer"}:
                name = _first_identifier_text(parent, source)
                if name and _NAME_HINTS.search(name):
                    return _Issue(
                        message=f"String literal assigned to suspicious identifier '{name}' (possible hardcoded secret).",
                        severity="high",
                    )

            # assignment: password = "..."
            if parent.type == "assignment_expression":
                left = parent.child_by_field_name("left")
                name = _first_identifier_text(left, source) if left is not None else None
                if name and _NAME_HINTS.search(name):
                    return _Issue(
                        message=f"String literal assigned to suspicious identifier '{name}' (possible hardcoded secret).",
                        severity="high",
                    )

        # 7) Lower-confidence keyword presence (no obvious value)
        if _NAME_HINTS.search(s) and ent >= 3.0 and len(s) >= 16:
            return _Issue(
                message="Suspicious keyword + moderately high entropy in string literal. Review for hardcoded secret.",
                severity="medium",
            )

        return None
