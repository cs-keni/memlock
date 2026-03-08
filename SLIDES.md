## Slide 1 – Title & Team

**Slide content**
- **MemLock: Static Security Analysis for C**
- Detecting memory and safety bugs in C using Python + Tree-sitter
- CS 433 – Computer Security
- Team: James Smith, Saint George Aufranc, Kenny Nguyen

**Speaker notes**
- MemLock is a static analyzer for C that flags classic vulnerabilities: buffer overflows, memory leaks, use-after-free, hardcoded secrets, format strings, etc.
- Python + Tree-sitter; no compilation or execution.

---

## Slide 2 – Motivation & Problem

**Slide content**
- **Why C?** Still everywhere (OS, embedded, critical services) but dangerous by design
  - Manual memory, raw pointers, unsafe lib functions
- **Problem**: Manual review doesn’t scale; bugs are easy to introduce, hard to spot
- **Goal**: Automated tool that parses C, detects vulnerability patterns, and produces actionable findings

**Speaker notes**
- C exposes low-level memory; small mistakes → critical vulnerabilities.
- We want consistent, repeatable detection without running the program.

---

## Slide 3 – How It Works

**Slide content**
- **Pipeline**
  1. **CLI** – file or directory input
  2. **Traversal** – find `.c` files
  3. **Parser** – Tree-sitter C → AST
  4. **Rules Engine** – run vulnerability rules over AST
  5. **Reporting** – findings by file, severity, snippets
- **Stack**: Python, Tree-sitter, Typer (CLI), Rich (output)

**Speaker notes**
- No compilation or execution; everything is AST-based.
- Modular: add rules without changing the pipeline.

---

## Slide 4 – What We Detect (8 Rules)

**Slide content**
- `unsafe-functions` – banned calls (gets, strcpy, sprintf, etc.)
- `buffer-overflow` – out-of-bounds writes, risky memcpy
- `memory-management` – leaks, double-free
- `use-after-free` – dereference after free
- `hardcoded-secrets` – passwords/tokens in strings
- `integer-overflow` – risky arithmetic
- `null-checks` – missing NULL guards on heap pointers
- `format-string` – dangerous printf/scanf usage

**Speaker notes**
- Each rule walks the AST and emits findings. Maps to real CWEs (e.g., CWE-119, CWE-416, CWE-134).

---

## Slide 5 – Demo

**Slide content**
- **Live demo**
- Run MemLock on vulnerable vs safe test files
- Show rich output: grouped by file, severity, snippets
- **Commands**
  - `python -m scanner.main tests/vulnerable --format rich --verbose`
  - `python -m scanner.main tests/safe --format rich`

**Speaker notes**
- Run both commands. Narrate: what’s wrong in vulnerable files, how safe versions fix it.
- Shows correctness (catches issues) and precision (doesn’t flag safe code).

---

## Slide 6 – Summary & Q&A

**Slide content**
- **Recap**
  - MemLock: Python static analyzer for C
  - 8 vulnerability rules, AST-based, rich reporting
  - Catches real issues; extensible design
- **Limitations**: Static-only, function-local analysis, heuristic rules
- **Questions?**

**Speaker notes**
- Brief recap. Invite questions on rules, architecture, or extensions.
