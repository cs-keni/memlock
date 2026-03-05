## MemLock User Manual

MemLock is a Python-based static analysis tool that scans C source code for common security vulnerabilities such as buffer overflows, memory management bugs, use-after-free, hardcoded secrets, missing NULL checks, integer overflow, and unsafe format strings.

This manual explains how to install, run, and interpret MemLock for typical coursework and demo scenarios.

---

## 1. Prerequisites & Installation

- **Python**: 3.9 or higher
- **OS**: Linux, macOS, or Windows (PowerShell or Git Bash recommended on Windows)
- **Git**: Only needed if you are cloning the repository yourself

### 1.1. Clone and set up the project

If you are using the project from source:

```bash
git clone <repository-url>
cd memlock
```

Create and activate a virtual environment (recommended):

```bash
python -m venv venv

# On Windows (PowerShell or cmd)
venv\Scripts\activate

# On macOS / Linux
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

> If you plan to run the Python unit tests as well, also install development dependencies:
> ```bash
> pip install -r requirements-dev.txt
> ```

---

## 2. Running the Scanner

MemLock is currently exposed as a Typer CLI app in `scanner/main.py`.

You can run it directly with Python:

```bash
python -m scanner.main analyze path/to/target
```

Where:
- `path/to/target` is either:
  - a single `.c` file, or
  - a directory containing one or more `.c` files (MemLock will recursively discover them).

### 2.1. Basic examples

Analyze a single file:

```bash
python -m scanner.main analyze tests/vulnerable/easy_gets_unsafe.c
```

Analyze an entire directory of C files:

```bash
python -m scanner.main analyze ./tests/vulnerable
```

Scan both safe and vulnerable examples (great for demos):

```bash
python -m scanner.main analyze ./tests
```

### 2.2. Output formats

MemLock currently supports two output formats via the `--format` (`-f`) option:

- **`rich`** (default): nicely formatted, colorized, grouped output using `rich`
- **`simple`**: grep-like plain text, easier to copy into other tools

Examples:

```bash
# Rich, colorized output (default)
python -m scanner.main analyze ./tests

# Explicit rich format
python -m scanner.main analyze ./tests --format rich

# Simple, grep-style findings per line
python -m scanner.main analyze ./tests --format simple
```

### 2.3. Verbose remediation hints

Use the `--verbose` (`-v`) flag to show remediation hints for certain rules (e.g., unsafe functions, use-after-free):

```bash
python -m scanner.main analyze ./tests/vulnerable --verbose
```

Verbose mode:
- Shows per-rule **“Fix”** hints (e.g., replace `gets` with `fgets`, set pointers to `NULL` after `free`, etc.).
- Is especially useful when demonstrating the tool to an audience or teaching how to fix each kind of bug.

---

## 3. Understanding the Output

MemLock’s **rich output** groups findings by file and shows a summary at the end.

For each file, you will see:

- A panel with the file path (e.g., `memlock/tests/vulnerable/easy_gets_unsafe.c`)
- A table with columns:
  - **Line**: 1-based line number
  - **Col**: 1-based column
  - **Severity**: e.g., `HIGH`, `MEDIUM`, `WARNING`, `INFO`
  - **Rule**: the rule identifier in brackets (e.g., `[unsafe-functions]`)
  - **Message**: human-readable explanation
- Optionally, one or more lines with a code snippet for each finding

At the bottom, MemLock prints:

- A **Files Summary** table:
  - Each analyzed file
  - Status: `UNSAFE` (one or more findings) or `OK` (no findings)
  - Number of findings per file
- A **Summary** panel:
  - Total findings
  - Count by severity level (e.g., `2 high | 5 warning | 1 low`)

### 3.1. Example rich output (conceptual)

You might see something like:

```text
memlock/tests/vulnerable/easy_gets_unsafe.c

Line  Col  Severity  Rule                Message
----  ---  --------  -----------------   -----------------------------------------------
10    5    WARNING   [unsafe-functions]  Unsafe function 'gets' may lead to overflow...

  |--     gets(buf);

Files Summary
File                                           Status  Findings
--------------------------------------------   ------  --------
memlock/tests/vulnerable/easy_gets_unsafe.c   UNSAFE  1
memlock/tests/safe/easy_fgets_safe.c          OK      0

Summary
1 finding | 0 high | 1 warning | 0 low
```

### 3.2. Simple format

With `--format simple`, each finding is a single line:

```text
path/to/file.c:LINE:COL: SEVERITY [rule-id] message
```

Example:

```text
tests/vulnerable/easy_gets_unsafe.c:10:5: WARNING [unsafe-functions] Unsafe function 'gets' may lead to buffer overflow or undefined behavior; use a safe alternative.
```

This is useful if you want to:
- Pipe into `grep`/`rg`
- Integrate with editors that understand `file:line:col` patterns

---

## 4. What MemLock Detects

MemLock focuses on 8 vulnerability categories. Each category is implemented as a separate **rule**.

For each finding, you’ll see the associated rule ID:

- **`unsafe-functions`**: Use of dangerous standard library functions (e.g., `gets`, `strcpy`, `sprintf`, unbounded `scanf`).
- **`buffer-overflow`**: Array bounds violations and unsafe buffer operations (e.g., `buf[8]` when `buf` has size 8).
- **`memory-management`**: Memory leaks and double frees (e.g., `malloc` without `free`, or `free(p)` called multiple times).
- **`use-after-free`**: Dereferencing a pointer after it was freed.
- **`hardcoded-secrets`**: Hardcoded passwords, API keys, bearer tokens, and high-entropy “token-like” strings.
- **`integer-overflow`**: Arithmetic that may overflow/underflow without obvious bounds checks.
- **`null-checks`**: Dereferencing a pointer returned from `malloc` without an apparent `NULL` check.
- **`format-string`**: Classic format string vulnerabilities (e.g., `printf(user_input)` or unsafe `scanf` format strings).

You can see a concise summary of these in `README.md` under **Detected Vulnerabilities**.

---

## 5. Suggested Demo Flows

These flows are useful for a class presentation or quick sanity check.

### 5.1. Vulnerable vs. safe files comparison

1. Run MemLock on the **vulnerable** directory:
   ```bash
   python -m scanner.main analyze ./tests/vulnerable --format rich --verbose
   ```
2. Point out:
   - The high-level summary: many files marked `UNSAFE`.
   - One or two concrete examples (e.g., `easy_gets_unsafe.c` or `buffer_overflow_unsafe.c`).
3. Then run MemLock on the **safe** directory:
   ```bash
   python -m scanner.main analyze ./tests/safe --format rich
   ```
4. Show that most or all files are `OK`, demonstrating that the rules are not trivially noisy.

### 5.2. Deep-dive into a single vulnerability type

Pick one file from `tests/vulnerable/` and the corresponding “safe” variant from `tests/safe/`:

- For buffer overflow:
  - `tests/vulnerable/buffer_overflow_unsafe.c`
  - `tests/safe/buffer_overflow_safe.c`
- For memory leaks:
  - `tests/vulnerable/memory_management_unsafe.c`
  - `tests/safe/memory_management_safe.c`
- For use-after-free:
  - `tests/vulnerable/use_after_free_unsafe.c`
  - `tests/safe/use_after_free_safe.c`

Run MemLock on each file individually and explain:
- What pattern the rule is looking for.
- Why the vulnerable file is flagged.
- How the safe file fixes the pattern.

---

## 6. Limitations & Expected Behavior

MemLock is a **static analysis tool** with a **fixed rule set**, not a formal verifier or a runtime detector. Some important limitations:

- **Heuristic-based**: It looks for patterns in the AST, not full program proofs.
- **False positives**: Some safe code may still be flagged if it looks similar to a known bad pattern.
- **False negatives**: Complex vulnerabilities (especially across multiple functions or modules) may not be detected.
- **Scope**: Many rules analyze behavior within a single function; they do not attempt full inter-procedural dataflow analysis.
- **Runtime behavior**: MemLock does not execute the program or understand actual runtime values; it works only from source.

These tradeoffs are intentional for a course project: they keep the tool understandable, fast, and demonstrable while still being **useful enough to teach and catch common mistakes**.

---

## 7. Running Python Unit Tests (Optional)

If you want to validate the rule implementations themselves:

1. Ensure development dependencies are installed:
   ```bash
   pip install -r requirements-dev.txt
   ```
2. Run the full test suite:
   ```bash
   pytest
   ```
3. Or test a single rule:
   ```bash
   pytest tests/test_buffer_overflow.py -v
   ```

These tests:
- Use small in-memory C programs to validate each rule.
- Assert that findings have correct rule IDs, messages, and locations.
- Help demonstrate that MemLock’s rules are **systematically tested**, not just manually tried once.

> If `pytest` is not available in your environment, you can still run the scanner directly as described in sections 2–5.

---

## 8. Troubleshooting

- **`ModuleNotFoundError` for `tree_sitter` or `tree_sitter_c`**  
  - Make sure you installed dependencies with `pip install -r requirements.txt` in the active virtual environment.

- **`python -m scanner.main` fails with “No module named scanner”**  
  - Confirm your current working directory is the project root (the directory that contains the `scanner/` folder).
  - On Windows, if using PowerShell or Git Bash, ensure the virtual environment is activated.

- **No findings but you expect some**  
  - Double-check that:
    - You pointed MemLock at the correct directory.
    - The directory actually contains `.c` files (headers alone are not scanned by default).
  - Try running on `./tests/vulnerable` to verify the tool is functioning.

- **Too many findings / noisy output**  
  - Remember that this is a teaching-focused tool. In a real-world scenario you would:
    - Disable noisy rules (future `--skip` support).
    - Tune severities and filters (see `FUTURE-ENHANCEMENTS.md` for ideas).

---

## 9. When to Use MemLock

MemLock is most helpful when:

- You are working on **C assignments** that involve manual memory management or string handling.
- You want a **quick sanity check** before turning in code.
- You are demonstrating **classic C vulnerabilities** in a classroom or presentation.
- You want to explore how a **Python-based static analyzer** can reason about C using Tree-sitter.

It is not a replacement for:

- Compiler warnings
- Sanitizers (ASan, Valgrind, etc.)
- Professional-grade enterprise analyzers

But it **bridges the gap** between theory and practice in a 10-week course: it is small enough to understand, yet rich enough to detect real, non-trivial security issues.

