# MemLock - C Static Security Analysis Tool

## Project Overview

The goal of this project is to automatically detect common security vulnerabilities in C source code at the source-code level, without executing the program.

C is especially prone to security issues due to manual memory management and unsafe standard library functions. Manually reviewing C code for vulnerabilities is time-consuming and error-prone, so this project aims to assist developers by flagging potentially dangerous patterns early.

This is not a compiler and not a formal verification tool. The scanner does best-effort pattern detection, similar in spirit to a lightweight static analyzer.

**Key Insight**: Most real-world C security tools (Semgrep, Bandit, Flawfinder) are written in Python, not C. This project follows that same approach, leveraging Python's rich ecosystem for parsing and analysis.

## Implementation Language

**Primary implementation language: Python**

We use Python because:
- Tree-sitter (AST parsing) has excellent Python bindings
- Real-world security tools use Python (Semgrep, Bandit, Flawfinder)
- Rich ecosystem for CLI (Typer), output formatting (Rich), and data validation (Pydantic)
- Easier to maintain and extend than C

The tool analyzes **C code** but is implemented in **Python**.

## Core Goals

The tool should:

- Parse and analyze real-world C source code using Tree-sitter
- Traverse directories and handle multi-file C projects
- Detect known vulnerability patterns via modular rule system
- Output clear, readable warnings with file names and line numbers
- Support multiple output formats (Rich console, JSON, SARIF)
- Be robust (should not crash on malformed or partial code)

## What the Tool Does (High-Level)

1. Accepts a directory or file path via CLI (Typer)
2. Recursively finds .c files
3. Parses each file using Tree-sitter-C to build an AST
4. Applies vulnerability detection rules (modular, extensible)
5. Outputs a grouped security report (Rich console or JSON/SARIF)

## Vulnerability Types (Scope)

The scanner focuses on 8 common, well-known C vulnerabilities:

### 1. Unsafe Function Usage

**AST target**: `call_expression`

**Strategy**:
- Detect function calls where function name is in banned set
- `UNSAFE_FUNCS = {"gets", "strcpy", "sprintf", "scanf"}`

**Example**:
```c
strcpy(dest, src);  // Flagged
```

**Priority**: Easiest module. Implement first.

### 2. Buffer Overflow Risks

**AST targets**:
- `array_declarator`
- `subscript_expression`
- `assignment_expression`

**Strategy**:
- Record array sizes from declarations
- Flag writes using indices ≥ declared size
- Flag loops that exceed bounds

**Note**: Heuristic-based, not perfect (acceptable for scope).

### 3. Memory Management Errors

**AST targets**:
- `call_expression` (malloc, free)
- `identifier`

**Strategy**:
- Track allocated variables per function scope
- Track frees
- Emit findings for:
  - **Leak**: allocated but never freed
  - **Double free**: freed twice

**Note**: Keep scope function-local to reduce false positives.

### 4. Use-After-Free

**AST targets**:
- `free(p)` followed by usage of `p` in:
  - `subscript_expression`
  - `pointer_expression`

**Strategy**:
- Track freed identifiers
- Flag later dereferences of freed pointers

**Note**: Explicitly document this is heuristic-based detection.

### 5. Hardcoded Secrets

**AST target**: `string_literal`

**Strategy**:
- Regex match against patterns:
  - `password`, `secret`, `apikey`
  - Long entropy strings (potential tokens)

**Note**: Very demo-friendly vulnerability type.

### 6. Integer Overflow/Underflow

**AST targets**:
- `binary_expression`
- `call_expression` (malloc with arithmetic)

**Strategy**:
- Detect arithmetic used inside allocation size
- Flag multiplication/addition without bounds check
- Conservative warnings only

### 7. Missing NULL Checks

**AST targets**:
- `call_expression` (malloc)
- `if_statement`

**Strategy**:
- Detect dereference of pointer without NULL guard
- Only check immediate usage after allocation

**Note**: Good medium-difficulty rule.

### 8. Format String Vulnerabilities

**AST target**: `call_expression`

**Strategy**:
- Check if format argument is NOT a string literal
- Flag `printf(user_input)` patterns

**Example**:
```c
printf(user_input);  // Flagged
printf("%s", user_input);  // Safe
```

**Note**: Classic, very teachable vulnerability.

## Architecture

### Project Structure

```
scanner/
├── main.py                 # Typer CLI entry
├── config.py               # Enabled rules, severity mapping
├── traversal.py            # Walk directories, collect .c files
├── parser.py               # Tree-sitter setup + AST parsing
├── context.py              # Per-file analysis context
│
├── findings/
│   ├── models.py           # Pydantic Finding, Location, Severity
│   └── sarif.py            # Optional SARIF/JSON exporter
│
├── rules/
│   ├── base.py             # Rule interface
│   ├── unsafe_functions.py
│   ├── buffer_overflow.py
│   ├── memory_management.py
│   ├── use_after_free.py
│   ├── hardcoded_secrets.py
│   ├── integer_overflow.py
│   ├── null_checks.py
│   └── format_string.py
│
├── reporting/
│   ├── console.py           # Rich output
│   └── summary.py
│
└── tests/
    ├── vulnerable/
    └── safe/
```

### Rule Interface (Super Important)

Every rule implements a clean interface:

```python
class Rule(ABC):
    id: str
    name: str
    description: str
    severity: Severity

    @abstractmethod
    def analyze(self, tree, context) -> list[Finding]:
        pass
```

**Why this matters**:
- Clean modularity
- Easy enable/disable per rule
- Makes "8 vulnerabilities" trivial to explain
- Separation of concerns: rules only produce findings, no printing/formatting

### Finding Contract

All rules produce standardized Finding objects:

```python
class Finding(BaseModel):
    rule_id: str
    title: str
    description: str
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    file: str
    line: int
    column: int
    snippet: str | None
```

**Key principle**: Rules only produce Findings. No printing, no formatting, no CLI logic. This keeps the architecture clean and testable.

### CLI UX (Typer + Rich)

**Example usage**:
```bash
cscan analyze ./project --severity medium --format rich
cscan analyze ./project --format json
```

**Rich output features**:
- Group by file
- Color by severity
- Show code snippet
- Summary statistics

This will impress during demo and provides excellent developer experience.

## Technology Stack

### Core Dependencies

- **tree-sitter** + **tree-sitter-c**: AST parsing for C code
- **tree_sitter_languages**: Language bindings
- **Typer**: Modern CLI framework
- **Rich**: Beautiful terminal output
- **Pydantic**: Data validation and models
- **JSON/SARIF**: Structured output formats

### Why Tree-sitter?

- Fast, incremental parsing
- Handles incomplete/malformed code gracefully
- Excellent Python bindings
- Used by real-world tools (GitHub's code navigation)
- Tree-sitter-C provides accurate C AST

## Implementation Constraints

- Static analysis only (no execution, no fuzzing)
- Detection is pattern-based, not perfect
- False positives are acceptable but should be minimized
- Clear documentation and explanations are preferred over completeness
- Heuristic-based detection is acceptable (document limitations)

## Output Requirements

Each detected issue includes:
- File name
- Line number and column
- Vulnerability type (rule ID)
- Short explanation
- Severity level (LOW / MEDIUM / HIGH)
- Code snippet (optional)

Output formats:
- **Rich console**: Grouped by file, color-coded, human-readable
- **JSON**: Machine-readable for integration
- **SARIF**: Standard format for security tools

## Evaluation Plan

The project will be evaluated by:
- Running the scanner on intentionally vulnerable C programs
- Measuring:
  - True positives
  - False positives
  - False negatives
- Discussing tradeoffs between precision and recall
- Demonstrating each of the 8 vulnerability types

## Explicit Non-Goals

- Not a full compiler
- Not language-agnostic (C only)
- Not a proof of security
- Not expected to catch all vulnerabilities
- No runtime execution or sandboxing
- No inter-procedural analysis (function-local scope only)

## Final Deliverables

- Working Python-based C vulnerability scanner
- Sample vulnerable C test programs (one per vulnerability type)
- Evaluation metrics and analysis
- Final report and presentation
- Demo showcasing all 8 vulnerability types

## Important Mindset

When helping with code:
- Prefer clarity over cleverness
- Favor modular, readable Python code
- Handle errors gracefully
- Assume input code may be messy or incomplete
- Treat this as a security assistant tool, not a correctness checker
- Keep rules independent and testable
- Rules produce Findings only - no side effects

## Development Priorities

1. **Start with Unsafe Functions** - Easiest to implement, good proof of concept
2. **Hardcoded Secrets** - Very demo-friendly, quick win
3. **Format String** - Classic vulnerability, teachable
4. **Memory Management** - Core C issue, moderate complexity
5. **Buffer Overflow** - Important but heuristic-based
6. **Use-After-Free** - Advanced, explicitly document limitations
7. **NULL Checks** - Medium difficulty, good coverage
8. **Integer Overflow** - Conservative approach, last priority

## Future Enhancements (Stretch Goals)

- Support for scanning GitHub repositories via URL
- Integration with CI/CD pipelines
- Support for additional vulnerability patterns
- Configuration file for custom rules
- Inter-procedural analysis
- Taint analysis for more accurate detection
