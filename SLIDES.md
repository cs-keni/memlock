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

| Rule | What it looks for | How it finds it | Why it is needed |
|------|-------------------|-----------------|------------------|
| **unsafe-functions** | Banned C library calls (gets, strcpy, strcat, sprintf, unbounded scanf/sscanf) | Walks AST for `call_expression` nodes; extracts function name; checks against banned set; for scanf, inspects format literal for unbounded %s/%[...] | These functions have no bounds checking → buffer overflows (CWE-119) |
| **buffer-overflow** | Out-of-bounds array writes, risky memcpy/memmove, loop index exceeding array size | Builds map of array sizes from `array_declarator`; checks `assignment_expression` subscripts and `for_statement` loop bounds; validates memcpy length vs dest size | Prevents memory corruption, RCE (CWE-119) |
| **memory-management** | Memory leaks (malloc without free), double free | Per-function: collects allocations (malloc/calloc/realloc + wrapper functions) and frees; flags unfreed vars and duplicate free() calls | Leaks exhaust memory; double free is undefined behavior (CWE-415, CWE-404) |
| **use-after-free** | Use of pointer after free() in same function | Builds timeline of free() calls and identifier uses; flags uses that occur after a free of same var; skips safe `p = NULL` after free | Prevents use-after-free exploits (CWE-416) |
| **hardcoded-secrets** | Passwords, API keys, JWTs, PEM blocks in string literals | Scans `string_literal` nodes; regex for JWT/AWS/GCP patterns, PEM blocks, key=value; entropy check for token-like strings; checks var names (password, token, etc.) | Secrets in source get committed → credential theft (CWE-798) |
| **integer-overflow** | Arithmetic (+, -, *, /, %, <<, >>) without bounds checks | Finds `binary_expression` with arithmetic ops; checks if preceded by if with relational op or INT_MAX/SIZE_MAX; skips sizeof-based expr | Overflow can corrupt buffers or bypass checks (CWE-190) |
| **null-checks** | Dereference of malloc pointer without NULL guard | Tracks vars assigned from malloc/calloc/realloc; finds *p, p->field, p[i]; checks if inside if(ptr!=NULL) or after if(!ptr)return | Prevents NULL dereference crashes (CWE-476) |
| **format-string** | Non-literal format strings, %n, unbounded scanf %s | Finds printf/scanf-family calls; checks format arg: non-literal → flag; literal with %n or unbounded %s/%[...] → flag | Prevents format-string attacks (CWE-134) |

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
