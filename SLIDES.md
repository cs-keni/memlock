## Slide 1 – Title & Team

**Slide content**
- **MemLock: Static Security Analysis for C**
- Detecting memory and safety bugs in C source code using Python + Tree-sitter
- CS 433 – Computer Security
- Team: James Smith, Saint George Aufranc, Kenny Nguyen

**Speaker notes**
- Introduce the project as **MemLock**, a static analysis tool for C programs.
- Emphasize that it targets **classic security vulnerabilities** in C: buffer overflows, memory mismanagement, use-after-free, hardcoded secrets, format strings, etc.
- Mention that the implementation is in **Python**, but it analyzes **C source code** using Tree-sitter.
- State the course and team members so the audience knows who built what they’re about to see.

---

## Slide 2 – Motivation: Why C Needs Help

**Slide content**
- C is powerful but **dangerous by design**
  - Manual memory management
  - Raw pointers, unchecked array access
  - Unsafe standard library functions
- Security bugs are:
  - Easy to introduce
  - Hard to spot by eye
  - Often catastrophic (RCE, data leaks)

**Speaker notes**
- Explain that C is still everywhere: OS kernels, embedded systems, performance-critical services.
- Because C exposes low-level memory directly, **small mistakes** can become **critical vulnerabilities**: buffer overflows, null dereferences, leaks, use-after-free, etc.
- Manual code review doesn’t scale well: as projects grow beyond a few files, it’s impractical to catch all issues by hand.
- Frame the project as answering: *“Can we automatically flag common dangerous patterns so developers see them early?”*

---

## Slide 3 – Problem Statement & Goals

**Slide content**
- **Problem**: Manually finding C security bugs is:
  - Slow and error-prone
  - Hard to scale to multi-file projects
  - Dependent on individual reviewer expertise
- **Goal**: Build an automated tool that:
  - Parses real C code
  - Detects common vulnerability patterns
  - Produces clear, actionable findings for developers

**Speaker notes**
- State the core problem: we want **consistent, repeatable detection** of common C vulnerabilities without running the program.
- Highlight that we target **source-level patterns**, not binary analysis and not runtime instrumentation.
- Clarify success criteria:
  - The tool must handle **multi-file projects**.
  - It should cover a **set of high-impact vulnerability types**.
  - It must produce output that a developer can actually understand and act on.

---

## Slide 4 – Our Approach in One Picture

**Slide content**
- High-level pipeline:
  1. **CLI (Typer)** – takes a file or directory
  2. **Traversal** – walks folders, finds `.c` files
  3. **Parser (Tree-sitter-C)** – builds ASTs
  4. **Rules Engine** – runs each vulnerability rule over the AST
  5. **Reporting (Rich)** – groups findings by file, colors by severity, prints summary

**Speaker notes**
- Walk through this pipeline slowly; this is the mental model for the whole project.
- Emphasize that we do **no compilation and no execution** – everything is about the **abstract syntax tree (AST)**.
- Point out that each phase is modular:
  - If you change traversal, rules and reporting don’t need to change.
  - If you add a new rule, the CLI doesn’t know or care – it simply iterates over enabled rule instances from `config.py`.
- This modularity is what makes the project extensible and “tool-like” rather than a one-off script.

---

## Slide 5 – Technology Stack & Design Choices

**Slide content**
- **Implementation language**: Python 3.9+
- **Key libraries**
  - Tree-sitter + tree-sitter-c (C AST parsing)
  - Typer (CLI)
  - Rich (terminal UI)
  - Pydantic (Finding / Location models)
- **Why Python?**
  - Mirrors real tools like Semgrep / Flawfinder
  - Fast to iterate, easy to read and test

**Speaker notes**
- Explain that most modern security analyzers for C are **not** written in C; they are built in higher-level languages with good parsing libraries.
- Tree-sitter gives us a **robust, incremental parser** for C that:
  - Handles partially valid code
  - Provides a rich AST, not just text matching
- Typer gives a clean CLI (`analyze` command, options like `--format` and `--verbose`).
- Rich gives an effective UX: color-coded severities, grouped output, summary tables – this helps the tool feel like a **real product**, not just a prototype.

---

## Slide 6 – Architecture & Code Structure

**Slide content**
- **Project layout (simplified)**
  - `scanner/main.py` – CLI entry (`analyze` command)
  - `scanner/config.py` – which rules are enabled
  - `scanner/traversal.py` – find `.c` files, skip `build/`, `tests/`, etc.
  - `scanner/parser.py` – Tree-sitter C parser
  - `scanner/context.py` – per-file `FileContext` (path, bytes, AST)
  - `scanner/findings/models.py` – `Finding` + `Location`
  - `scanner/rules/*.py` – one file per vulnerability type
  - `scanner/reporting/console.py` – Rich output, summary tables

**Speaker notes**
- Briefly describe each layer and how they talk:
  - `main.py` orchestrates: calls traversal → parsing → rules → reporting.
  - `config.py` is the central place where we decide which rules run by default.
  - `FileContext` in `context.py` is the object that rules consume: it holds the AST and helper functions like `get_source_span` and `get_line_col`.
- Emphasize that **rules never print directly** and don’t know about CLI flags – they just produce `Finding` objects. This separation is important for correctness and testability.

---

## Slide 7 – Rule Set Overview (8 Vulnerability Types)

**Slide content**
- Implemented rules:
  1. `unsafe-functions` – banned C library calls
  2. `buffer-overflow` – out-of-bounds array writes and risky copies
  3. `memory-management` – leaks and double-free
  4. `use-after-free` – dereference after `free`
  5. `hardcoded-secrets` – passwords / tokens in strings
  6. `integer-overflow` – risky arithmetic without bounds checks
  7. `null-checks` – missing NULL guards on heap pointers
  8. `format-string` – dangerous printf/scanf usage

**Speaker notes**
- Walk through the list briefly, mapping each rule to the **type of bug** and a **real-world CWE** (e.g., buffer overflow → CWE-119, use-after-free → CWE-416, format string → CWE-134).
- Emphasize that each rule is implemented in its own module under `scanner/rules/`, following a consistent pattern: walk the AST, detect a pattern, emit one or more findings.
- This slide sets up the next few deep-dive slides where you’ll pick 2–3 rules to explain more thoroughly.

---

## Slide 8 – Deep Dive: Unsafe Functions & Format Strings

**Slide content**
- **UnsafeFunctionsRule**
  - Flags calls to `gets`, `strcpy`, `strcat`, `sprintf`, unbounded `scanf`/`sscanf`
  - Uses AST `call_expression` nodes and function-name extraction
- **FormatStringRule**
  - Flags non-literal format strings: `printf(user_input);`
  - Warns on `%n` and unbounded `%s` / `%[...]` in `scanf`-family

**Speaker notes**
- Explain how `UnsafeFunctionsRule` works:
  - It walks the AST, finds `call_expression` nodes, extracts the **bare function name**, and checks if it is in a banned set.
  - For `scanf`-like functions, it inspects the **format string literal** and only flags it if there is an unbounded `%s`/`%[...]` (e.g., `%s` without width vs `%15s` which is allowed).
- Explain `FormatStringRule`:
  - It determines **which argument is the format string** for `printf`, `fprintf`, `snprintf`, and `scanf`-family calls.
  - If the format is **not a string literal** (e.g., a variable or user input), it flags a classic format-string vulnerability.
  - It also inspects literal formats for `%n` (dangerous because it writes to memory) and for obviously unbounded `scanf` patterns.
- Emphasize that both rules show how the tool is doing **real AST reasoning**, not just regex over text.

---

## Slide 9 – Deep Dive: Buffer Overflows & Memory Management

**Slide content**
- **BufferOverflowRule**
  - Tracks array declarations: `char buf[8];`
  - Flags:
    - Direct out-of-bounds writes: `buf[8] = ...`
    - Loops where the index can exceed the array size
    - Risky `memcpy`/`memmove` lengths
- **MemoryManagementRule**
  - Detects:
    - Leaks: `malloc` without any `free` in the same function
    - Double frees: `free(p); free(p);`
  - Understands simple **allocating functions** and **freeing wrappers**

**Speaker notes**
- For `BufferOverflowRule`, explain the two-phase strategy:
  - First pass: build a map from variable name to array size by looking at `array_declarator` nodes with constant sizes.
  - Second pass: inspect `assignment_expression` and `for` loops for subscript expressions; if an index can go beyond the stored size, emit a high-severity finding.
  - For `memcpy`/`memmove`, if the third argument is a constant and bigger than the destination array’s known size, it’s a definite overflow.
- For `MemoryManagementRule`:
  - It scans each **function** independently.
  - Tracks which variables receive allocations (either directly from `malloc`/`calloc`/`realloc` or from helper functions that wrap those).
  - Tracks all `free` calls and identifies:
    - Variables that are freed more than once (double free).
    - Variables that are never freed before function exit (possible leak).
- This shows that MemLock is not just pattern-matching one line at a time; it performs **function-level reasoning** about allocations and frees.

---

## Slide 10 – Deep Dive: Use-After-Free & NULL Checks

**Slide content**
- **UseAfterFreeRule**
  - Finds `free(p)` and later uses of `p` in the same function
  - Skips safe patterns like `p = NULL` after `free(p)`
- **NullChecksRule**
  - Tracks pointers returned from `malloc`/`calloc`/`realloc`
  - Flags dereferences of those pointers without a visible `NULL` check
  - Understands common guard patterns:
    - `if (p == NULL) return;`
    - `if (!p) return;`
    - `if (p != NULL) { ... *p ... }`

**Speaker notes**
- Describe `UseAfterFreeRule`:
  - It constructs a timeline of events in a function: frees and identifier uses.
  - When it sees a dereference of a name that was previously freed, and they are in the same function, it emits a warning.
  - It intentionally treats `p = NULL` after `free(p)` as **safe hygiene** and does not flag that as a use-after-free.
- For `NullChecksRule`:
  - It first identifies which identifiers are **heap pointers** by seeing which variables are assigned from `malloc`/`calloc`/`realloc`.
  - Then it looks for pointer dereference patterns (pointer expressions and array subscripts) and checks whether they are **guarded** by a prior or surrounding `NULL` check.
  - If a dereference is not obviously protected, it warns about a potential NULL dereference.
- Emphasize that these rules capture **control-flow-sensitive** patterns, not just local syntax.

---

## Slide 11 – Output & Developer Experience

**Slide content**
- **CLI command**
  - `python -m scanner.main analyze ./project --format rich --verbose`
- **Rich output**
  - Grouped by file
  - Color-coded severities
  - Code snippets under each finding
  - File-by-file **“SAFE / UNSAFE”** summary
- Optional **simple** format:
  - `file.c:line:col: SEVERITY [rule] message`

**Speaker notes**
- Show a screenshot or live demo of the `rich` output:
  - Each file appears as a panel with a table of findings.
  - The bottom includes a **summary table** showing which files are safe and which contain findings.
- Emphasize how this improves usability:
  - Developers can quickly scan for the worst issues (by severity and file count).
  - The snippet gives immediate context without opening the file.
- Mention that the **simple** format is compatible with editors and CI systems that parse `file:line:col` style messages.

---

## Slide 12 – Demo Plan (Live or Recorded)

**Slide content**
- **Scenario 1: Vulnerable code**
  - Run MemLock on `tests/vulnerable/` (e.g., `easy_gets_unsafe.c`, `buffer_overflow_unsafe.c`)
  - Highlight a few findings and explain each rule’s reasoning
- **Scenario 2: Fixed code**
  - Run on `tests/safe/` equivalents
  - Show that they are reported as **OK**
- **Takeaway**: small code changes → tool’s verdict flips from UNSAFE to SAFE

**Speaker notes**
- Plan to actually run:
  - `python -m scanner.main analyze ./tests/vulnerable --format rich --verbose`
  - Then `python -m scanner.main analyze ./tests/safe --format rich`
- As you present the demo, narrate:
  - What vulnerability is in the vulnerable file (e.g., `gets`, unbounded loop index).
  - How the safe version solves it (e.g., using `fgets`, fixing loop bounds, adding `free`, adding NULL checks).
- Emphasize that this demonstrates both:
  - **Correctness**: the tool catches real issues.
  - **Precision**: it doesn’t complain about well-written safe code.

---

## Slide 13 – Evaluation: How Well Does It Work?

**Slide content**
- Evaluation methodology:
  - Use curated **safe vs. vulnerable** test pairs
  - Measure:
    - True positives (vulnerable flagged)
    - False negatives (vulnerable missed)
    - False positives (safe flagged)
- Observations:
  - High detection for straightforward patterns
  - Some false positives for very defensive or macro-heavy code (expected for heuristics)

**Speaker notes**
- Explain that you evaluated the tool on:
  - The custom test suite under `tests/` (easy/medium/hard, safe/vulnerable).
  - A mix of simple examples and more “enterprise-style” patterns with macros and wrappers.
- Discuss what went well:
  - For easy patterns (straightforward `gets`, obvious buffer overflows, simple leaks), detection is very reliable.
  - For complex flows, the tool sometimes misses subtle bugs, which you document as limitations.
- Stress that the goal for the class project is **usefulness + explainability**, not industrial-grade precision.

---

## Slide 14 – Limitations & Threat Model

**Slide content**
- **Static-only**: no execution, no runtime data
- **Function-local analysis**:
  - No deep inter-procedural or whole-program dataflow
- **Heuristic rules**:
  - May produce false positives and false negatives
- **Scope**:
  - C language only
  - Focused on 8 vulnerability families (not complete coverage)

**Speaker notes**
- Be transparent about what MemLock does **not** do:
  - It doesn’t run the program, fuzz inputs, or simulate dynamic behavior.
  - It doesn’t do deep taint analysis or cross-function alias tracking.
  - It’s tuned to be **conservative and understandable**, not perfect.
- Also mention that many false positives are still **educational**:
  - They force developers to look at potentially risky patterns.
  - For a teaching tool, this tradeoff is acceptable and even useful.

---

## Slide 15 – Future Enhancements

**Slide content**
- From `FUTURE-ENHANCEMENTS.md`:
  - **JSON / SARIF output** for CI and code-scanning platforms
  - **Severity filters** (`--severity-min`) and rule toggles (`--only`, `--skip`)
  - **Config file** and ignore patterns (`.memlock.yaml`, `.memlockignore`)
  - **Parallel scanning** and progress bars for large codebases
  - **Baseline support** to track only *new* findings

**Speaker notes**
- Highlight that the repo already documents a realistic roadmap:
  - Machine-readable outputs (JSON, SARIF) would let MemLock plug into GitHub code scanning or other security dashboards.
  - Config files and ignore patterns would make it more usable on large, messy real-world projects.
  - Parallelization and progress indicators matter as soon as you scan hundreds of files.
- This shows that the project isn’t just an academic exercise; it’s structured so that future contributors could evolve it into a more complete tool.

---

## Slide 16 – Lessons Learned

**Slide content**
- Technical lessons
  - Working with Tree-sitter ASTs and visitors
  - Modeling findings with Pydantic and keeping rules stateless
  - Designing clean separation between **rules**, **context**, and **reporting**
- Security lessons
  - How common C bugs actually look in real code
  - Tradeoffs between **precision** and **coverage** in static analysis

**Speaker notes**
- Reflect on the technical side:
  - Understanding the structure of the C AST and how to write robust tree walkers.
  - Designing APIs that make rules easy to implement and test (e.g., `FileContext`, `Finding`).
- Reflect on the security side:
  - Seeing how “toy” vulnerabilities map to real code constructs.
  - Realizing that static analysis always involves tradeoffs: you must choose where to be strict and where to be conservative.
- This slide is a good place to connect back to course concepts from CS 433.

---

## Slide 17 – Why MemLock Matters

**Slide content**
- Helps developers:
  - Catch **high-impact C bugs** early in development
  - Understand *why* patterns are dangerous, not just that they are
- Demonstrates:
  - A full static analysis pipeline built in one semester
  - Realistic, rule-based detection on top of Tree-sitter
  - A path from class project → real-world security tooling

**Speaker notes**
- Summarize the value proposition:
  - MemLock shows that with the right libraries and a clean design, a student team can build a tool that **looks and behaves like a real static analyzer**.
  - It makes abstract vulnerabilities concrete by pointing at specific lines and snippets.
- Emphasize that the project balances **ambition** (8 rules, full CLI, tests, reporting) with **focus** (C only, well-defined scope).
- This is the slide to sell that the project is not only academically correct, but practically useful.

---

## Slide 18 – Conclusion & Q&A

**Slide content**
- **Recap**
  - Problem: C security bugs are subtle and dangerous
  - Solution: MemLock, a Python-based static analyzer for C
  - Capabilities: 8 rule types, AST-based analysis, rich reporting, curated test suite
- **Questions?**

**Speaker notes**
- Briefly restate the arc of the talk:
  - Motivation → design → rule set → demo → evaluation → limitations → future work.
- Reinforce that MemLock is:
  - **Helpful**: catches real issues in real C code.
  - **Competent**: built on a modern parsing stack with a clear architecture.
  - **Extensible**: new rules and outputs can be added without redesigning the system.
- Invite questions about specific rules, architecture decisions, or how this could be extended for other languages or vulnerability classes.

