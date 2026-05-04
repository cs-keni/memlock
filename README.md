# MemLock

A Python-based static security analysis tool for C source code. MemLock parses C files into abstract syntax trees using Tree-sitter, then runs eight rule categories to surface memory-safety, secrets-exposure, and control-flow vulnerabilities — without compiling or executing the target program.

Built for CS433 - Computer Security.

---

## Screenshots

**Findings for a single file**
![Single-file findings](https://raw.githubusercontent.com/cs-keni/memlock/main/docs/screenshots/example-findings-single-file.png)

**Full directory scan summary**
![Scanner summary](https://raw.githubusercontent.com/cs-keni/memlock/main/docs/screenshots/scanner-findings-summary.png)

**CLI invocation**
![CLI input](https://raw.githubusercontent.com/cs-keni/memlock/main/docs/screenshots/cli-input.png)

---

## Detected Vulnerabilities

| # | Rule | What it catches |
|---|------|-----------------|
| 1 | `unsafe-functions` | Dangerous stdlib calls: `gets`, `strcpy`, `strcat`, `sprintf`, etc. |
| 2 | `buffer-overflow` | Array out-of-bounds writes, loop over-indexing, unbounded `scanf %s` |
| 3 | `memory-management` | Memory leaks, double-free, missing `free` |
| 4 | `use-after-free` | Pointer dereference after `free()` |
| 5 | `hardcoded-secrets` | Passwords, API keys, and tokens in source |
| 6 | `integer-overflow` | Arithmetic without bounds checks on involved variables |
| 7 | `null-checks` | Pointer dereference without NULL validation |
| 8 | `format-string` | `printf`-family calls with non-literal format strings |

---

## Installation

```bash
git clone https://github.com/cs-keni/memlock.git
cd memlock
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Usage

Run the scanner from the project root (so `scanner` is on the module path):

```bash
# Analyze a single file
python -m scanner.main analyze path/to/file.c

# Analyze all .c files under a directory
python -m scanner.main analyze ./project

# Plain text output (grep-friendly)
python -m scanner.main analyze ./project --format simple

# Show remediation hints for each finding
python -m scanner.main analyze ./project --verbose
```

Output defaults to the Rich colored format. Use `--format simple` to get bare `file:line:col: SEVERITY [rule] message` lines suitable for piping.

---

## Project Structure

```
memlock/
├── scanner/
│   ├── main.py           # Typer CLI + analysis orchestration
│   ├── config.py         # Rule registry and configuration
│   ├── traversal.py      # .c file discovery
│   ├── parser.py         # Tree-sitter AST setup
│   ├── context.py        # Per-file analysis context
│   ├── findings/
│   │   ├── models.py     # Pydantic Finding / Location models
│   │   └── sarif.py      # SARIF/JSON exporter (stub)
│   ├── rules/
│   │   ├── base.py
│   │   ├── buffer_overflow.py
│   │   ├── format_string.py
│   │   ├── hardcoded_secrets.py
│   │   ├── integer_overflow.py
│   │   ├── memory_management.py
│   │   ├── null_checks.py
│   │   ├── unsafe_functions.py
│   │   └── use_after_free.py
│   └── reporting/
│       ├── console.py    # Rich terminal output
│       └── summary.py
├── tests/
│   ├── safe/             # C files with no vulnerabilities
│   └── vulnerable/       # C files with intentional vulnerabilities
├── docs/
│   └── screenshots/
└── .github/workflows/ci.yml
```

---

## Development

```bash
pip install -r requirements-dev.txt

# Lint
ruff check .

# Type check
mypy scanner/

# Run all tests
pytest tests/

# Run tests for a specific rule
pytest tests/test_buffer_overflow.py -v
```

CI runs on every pull request via GitHub Actions: linting (`ruff`), type checking (`mypy`), and the full test suite. All checks must pass before merging.

---

## Team

- Kenny Nguyen
- James Smith
- Saint George Aufranc
