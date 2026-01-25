# MemLock - C Static Security Analysis Tool

## Project Overview

The goal of this project is to automatically detect common security vulnerabilities in C source code at the source-code level, without executing the program.

C is especially prone to security issues due to manual memory management and unsafe standard library functions. Manually reviewing C code for vulnerabilities is time-consuming and error-prone, so this project aims to assist developers by flagging potentially dangerous patterns early.

This is not a compiler and not a formal verification tool. The scanner does best-effort pattern detection, similar in spirit to a lightweight static analyzer.

## Core Goals

The tool should:

- Parse and analyze real-world C source code
- Traverse directories and handle multi-file C projects
- Detect known vulnerability patterns
- Output clear, readable warnings with file names and line numbers
- Be robust (should not crash on malformed or partial code)

## What the Tool Does (High-Level)

1. Accepts a directory or file path via CLI
2. Recursively finds .c files
3. Parses each file to understand:
   - Function definitions
   - Function calls
   - Basic structure (not full semantic analysis)
4. Applies vulnerability detection rules
5. Outputs a grouped security report

## Vulnerability Types (Scope)

The scanner focuses on common, well-known C vulnerabilities, including:

### 1. Unsafe Function Usage

Detect calls to dangerous standard library functions such as:
- `gets`
- `strcpy`, `strcat`
- `sprintf`, `vsprintf`
- `scanf` without bounds
- `memcpy` without size checks

### 2. Buffer Overflow Risks

Examples:
- Writing into fixed-size buffers without bounds checks
- Mismatched buffer sizes
- Obvious array overflows

### 3. Memory Management Issues

Examples:
- `malloc` without corresponding `free`
- Double free
- Use-after-free (basic pattern-based detection)
- Ignoring return values from allocation functions

### 4. Hardcoded Secrets

Examples:
- Hardcoded passwords, API keys, tokens, or credentials in source code
- Suspicious string literals or constants

## Implementation Constraints

- Primary implementation language: **C**
- Static analysis only (no execution, no fuzzing)
- Detection is pattern-based, not perfect
- False positives are acceptable but should be minimized
- Clear documentation and explanations are preferred over completeness

## Output Requirements

Each detected issue should include:
- File name
- Line number
- Vulnerability type
- Short explanation
- Severity level (Low / Medium / High)

Output should be:
- Grouped by file
- Human-readable (console output is fine)

## Architecture (Conceptual)

Modular design, for example:
- **CLI Module** – handles arguments and entry point
- **File Traversal Module** – collects .c files
- **Parser Module** – tokenizes / parses code
- **Analyzer Module** – applies vulnerability rules
- **Reporter Module** – formats output

## Evaluation Plan

The project will be evaluated by:
- Running the scanner on intentionally vulnerable C programs
- Measuring:
  - True positives
  - False positives
  - False negatives
- Discussing tradeoffs between precision and recall

## Explicit Non-Goals

- Not a full compiler
- Not language-agnostic
- Not a proof of security
- Not expected to catch all vulnerabilities
- No runtime execution or sandboxing

## Final Deliverables

- Working C vulnerability scanner
- Sample vulnerable C test programs
- Evaluation metrics and analysis
- Final report and presentation

## Important Mindset

When helping with code:
- Prefer clarity over cleverness
- Favor modular, readable C code
- Handle errors gracefully
- Assume input code may be messy or incomplete
- Treat this as a security assistant tool, not a correctness checker

## Future Enhancements (Stretch Goals)

- Support for scanning GitHub repositories via URL
- Integration with CI/CD pipelines
- Support for additional vulnerability patterns
- Configuration file for custom rules
- JSON/XML output formats for integration with other tools
