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

## Detailed Module Architecture

### Module Responsibilities

#### Core Modules (Top Level)

**`main.py`** - CLI Entry Point & Orchestration
- **Responsibilities**:
  - Parse CLI arguments using Typer
  - Initialize configuration from CLI flags
  - Coordinate the analysis pipeline
  - Handle errors and exit codes
  - Entry point for the `cscan` command
- **Dependencies**: `config`, `traversal`, `parser`, `rules`, `reporting`
- **Communicates via**: Function calls, returns aggregated findings
- **Key Functions**:
  - `main()` - Typer app entry point
  - `analyze_command()` - Main analysis orchestration

**`config.py`** - Configuration Management
- **Responsibilities**:
  - Store enabled/disabled rules
  - Map rule IDs to severity levels
  - Filter settings (severity thresholds, file patterns)
  - Rule registry (list of all available rules)
- **Dependencies**: None (pure configuration)
- **Communicates via**: Shared configuration object, imported by other modules
- **Key Classes/Functions**:
  - `Config` - Configuration dataclass
  - `get_enabled_rules()` - Returns list of enabled rule instances
  - `get_rule_by_id()` - Lookup rule by ID

**`traversal.py`** - File System Traversal
- **Responsibilities**:
  - Recursively walk directories
  - Filter for `.c` files (and optionally `.h` files)
  - Handle file I/O errors gracefully
  - Return list of file paths to analyze
- **Dependencies**: `os`, `pathlib`
- **Communicates via**: Function calls, returns list of file paths
- **Key Functions**:
  - `find_c_files(directory: Path) -> list[Path]` - Returns all .c files
  - `is_c_file(path: Path) -> bool` - File type check

**`parser.py`** - Tree-sitter AST Parsing
- **Responsibilities**:
  - Initialize Tree-sitter C language parser
  - Parse C source code into AST
  - Handle parse errors gracefully
  - Provide AST query utilities
  - Cache parser instances (performance)
- **Dependencies**: `tree_sitter`, `tree_sitter_languages`
- **Communicates via**: Function calls, returns AST tree objects
- **Key Classes/Functions**:
  - `CParser` - Parser wrapper class
  - `parse_file(file_path: Path) -> Tree` - Parse file to AST
  - `get_node_text(node, source_bytes) -> str` - Extract text from node

**`context.py`** - Analysis Context
- **Responsibilities**:
  - Store per-file analysis state
  - Track file path, source code, AST
  - Provide helper methods for AST navigation
  - Store file-level metadata (function definitions, variable scopes)
- **Dependencies**: `parser`, `findings.models`
- **Communicates via**: Shared context object passed to rules
- **Key Classes**:
  - `AnalysisContext` - Context dataclass
    - `file_path: Path`
    - `source_code: str`
    - `tree: Tree`
    - `functions: dict` - Function name -> AST node mapping
    - Helper methods for AST queries

#### Findings Module

**`findings/models.py`** - Data Models
- **Responsibilities**:
  - Define `Finding` Pydantic model (the contract)
  - Define `Severity` enum (LOW, MEDIUM, HIGH)
  - Define `Location` model (file, line, column)
  - Validation and serialization
- **Dependencies**: `pydantic`
- **Communicates via**: Shared data models, imported by all modules
- **Key Classes**:
  - `Severity` - Enum for severity levels
  - `Finding` - Main finding model (Pydantic BaseModel)
  - `Location` - Optional location model

**`findings/sarif.py`** - SARIF/JSON Export
- **Responsibilities**:
  - Convert `Finding` objects to SARIF format
  - Export findings to JSON file
  - Generate SARIF report structure
- **Dependencies**: `findings.models`
- **Communicates via**: Function calls, takes list of Findings, returns JSON string
- **Key Functions**:
  - `findings_to_sarif(findings: list[Finding]) -> dict` - Convert to SARIF
  - `export_sarif(findings: list[Finding], output_path: Path)` - Write SARIF file

#### Rules Module

**`rules/base.py`** - Rule Interface
- **Responsibilities**:
  - Define abstract `Rule` base class
  - Enforce rule contract (analyze method)
  - Provide common utilities for rules
  - Rule metadata (id, name, description, severity)
- **Dependencies**: `findings.models`, `ABC`
- **Communicates via**: Abstract base class, inherited by all rules
- **Key Classes**:
  - `Rule(ABC)` - Abstract base class
    - `id: str` - Unique rule identifier
    - `name: str` - Human-readable name
    - `description: str` - Rule description
    - `severity: Severity` - Default severity
    - `analyze(tree, context) -> list[Finding]` - Abstract method

**`rules/unsafe_functions.py`** - Unsafe Function Detection
- **Responsibilities**:
  - Detect calls to banned functions (gets, strcpy, etc.)
  - Identify function name from call_expression nodes
  - Generate findings for unsafe function usage
- **Dependencies**: `rules.base`, `findings.models`
- **Communicates via**: Inherits from `Rule`, returns list of Findings
- **Key Classes**:
  - `UnsafeFunctionsRule(Rule)` - Rule implementation
- **Implementation Details**:
  - Query AST for `call_expression` nodes
  - Extract function name (first child of call_expression)
  - Check against `UNSAFE_FUNCS` set
  - Create Finding for each match

**`rules/buffer_overflow.py`** - Buffer Overflow Detection
- **Responsibilities**:
  - Track array declarations and sizes
  - Detect array subscript operations
  - Flag potential out-of-bounds access
  - Analyze loop bounds
- **Dependencies**: `rules.base`, `findings.models`, `context`
- **Communicates via**: Inherits from `Rule`, uses `AnalysisContext` for scope info
- **Key Classes**:
  - `BufferOverflowRule(Rule)` - Rule implementation
- **Implementation Details**:
  - First pass: collect array declarations with sizes
  - Second pass: check subscript_expression against declared sizes
  - Heuristic: flag if index >= size (conservative)

**`rules/memory_management.py`** - Memory Leak & Double Free
- **Responsibilities**:
  - Track malloc() calls and their return values
  - Track free() calls
  - Detect leaks (malloc without free)
  - Detect double free (free called twice on same pointer)
- **Dependencies**: `rules.base`, `findings.models`, `context`
- **Communicates via**: Inherits from `Rule`, uses `AnalysisContext` for function scope
- **Key Classes**:
  - `MemoryManagementRule(Rule)` - Rule implementation
- **Implementation Details**:
  - Track allocations per function scope
  - Track frees per function scope
  - At function end, check for unfreed allocations
  - Track freed pointers to detect double free

**`rules/use_after_free.py`** - Use-After-Free Detection
- **Responsibilities**:
  - Track free() calls and freed pointers
  - Detect subsequent usage of freed pointers
  - Flag dereferences after free
- **Dependencies**: `rules.base`, `findings.models`, `context`
- **Communicates via**: Inherits from `Rule`, uses `AnalysisContext` for control flow
- **Key Classes**:
  - `UseAfterFreeRule(Rule)` - Rule implementation
- **Implementation Details**:
  - Track freed identifiers
  - Check subsequent pointer dereferences (subscript, member access)
  - Heuristic-based (may have false positives)

**`rules/hardcoded_secrets.py`** - Secret Detection
- **Responsibilities**:
  - Scan string literals for secret patterns
  - Detect passwords, API keys, tokens
  - Check for high-entropy strings
- **Dependencies**: `rules.base`, `findings.models`
- **Communicates via**: Inherits from `Rule`, returns Findings
- **Key Classes**:
  - `HardcodedSecretsRule(Rule)` - Rule implementation
- **Implementation Details**:
  - Query AST for `string_literal` nodes
  - Regex match against patterns (password, secret, api_key, token)
  - Optional: entropy calculation for long strings

**`rules/integer_overflow.py`** - Integer Overflow Detection
- **Responsibilities**:
  - Detect arithmetic in allocation sizes
  - Flag multiplication/addition without bounds checks
  - Conservative warnings only
- **Dependencies**: `rules.base`, `findings.models`
- **Communicates via**: Inherits from `Rule`, returns Findings
- **Key Classes**:
  - `IntegerOverflowRule(Rule)` - Rule implementation
- **Implementation Details**:
  - Check `binary_expression` in malloc() arguments
  - Flag multiplication/addition operations
  - Conservative: only flag obvious cases

**`rules/null_checks.py`** - Missing NULL Check Detection
- **Responsibilities**:
  - Detect malloc() return value usage
  - Check for NULL guard before dereference
  - Flag immediate dereference without check
- **Dependencies**: `rules.base`, `findings.models`, `context`
- **Communicates via**: Inherits from `Rule`, uses `AnalysisContext` for control flow
- **Key Classes**:
  - `NullChecksRule(Rule)` - Rule implementation
- **Implementation Details**:
  - Track malloc() return values
  - Check for if_statement with NULL check before dereference
  - Flag dereferences without preceding NULL check

**`rules/format_string.py`** - Format String Vulnerability
- **Responsibilities**:
  - Detect printf-style functions
  - Check if format string is a literal vs variable
  - Flag non-literal format strings
- **Dependencies**: `rules.base`, `findings.models`
- **Communicates via**: Inherits from `Rule`, returns Findings
- **Key Classes**:
  - `FormatStringRule(Rule)` - Rule implementation
- **Implementation Details**:
  - Query AST for printf, sprintf, fprintf calls
  - Check first argument: if string_literal → safe, else → flag
  - Handle variadic arguments

#### Reporting Module

**`reporting/console.py`** - Rich Console Output
- **Responsibilities**:
  - Format findings for terminal display
  - Group findings by file
  - Color-code by severity
  - Display code snippets
  - Use Rich library for beautiful output
- **Dependencies**: `findings.models`, `rich`
- **Communicates via**: Function calls, takes list of Findings, prints to console
- **Key Functions**:
  - `print_findings(findings: list[Finding], config: Config)` - Main output function
  - `format_finding(finding: Finding) -> str` - Format single finding
  - `group_by_file(findings: list[Finding]) -> dict` - Group findings

**`reporting/summary.py`** - Summary Statistics
- **Responsibilities**:
  - Calculate summary statistics (total findings, by severity, by rule)
  - Generate summary report
  - Display statistics table
- **Dependencies**: `findings.models`, `rich`
- **Communicates via**: Function calls, takes list of Findings, returns/prints summary
- **Key Functions**:
  - `generate_summary(findings: list[Finding]) -> dict` - Calculate stats
  - `print_summary(findings: list[Finding])` - Print summary table

### Communication Patterns & Data Flow

#### High-Level Flow

```
main.py (CLI)
    ↓
config.py (load configuration)
    ↓
traversal.py (find .c files)
    ↓
For each file:
    parser.py (parse to AST)
        ↓
    context.py (create AnalysisContext)
        ↓
    For each enabled rule:
        rule.analyze(tree, context) → list[Finding]
            ↓
    Aggregate all findings
        ↓
reporting/console.py or findings/sarif.py (output)
```

#### Detailed Communication

**1. Initialization (main.py → config.py)**
```python
# main.py
config = Config.from_cli_args(args)
enabled_rules = config.get_enabled_rules()  # Returns list of Rule instances
```

**2. File Discovery (main.py → traversal.py)**
```python
# main.py
c_files = traversal.find_c_files(Path(args.target))
# Returns: list[Path]
```

**3. Analysis Loop (main.py → parser.py → rules)**
```python
# main.py
for file_path in c_files:
    # Parse
    tree = parser.parse_file(file_path)  # Returns Tree-sitter Tree
    
    # Create context
    context = AnalysisContext(
        file_path=file_path,
        source_code=file_path.read_text(),
        tree=tree
    )
    
    # Run rules
    all_findings = []
    for rule in enabled_rules:
        findings = rule.analyze(tree, context)  # Returns list[Finding]
        all_findings.extend(findings)
```

**4. Output (main.py → reporting)**
```python
# main.py
if args.format == "rich":
    reporting.console.print_findings(all_findings, config)
    reporting.summary.print_summary(all_findings)
elif args.format == "json":
    findings.sarif.export_sarif(all_findings, output_path)
```

#### Shared Objects

**Configuration Object** (`config.Config`)
- Created in `main.py`
- Passed to rules (optional, for rule-specific config)
- Passed to reporting (for filtering, formatting)

**AnalysisContext** (`context.AnalysisContext`)
- Created per file in `main.py` or `parser.py`
- Passed to each rule's `analyze()` method
- Contains: file_path, source_code, tree, helper methods

**Finding Objects** (`findings.models.Finding`)
- Created by rules
- Collected in `main.py`
- Passed to reporting modules
- Immutable (Pydantic model)

**Rule Instances** (`rules.base.Rule`)
- Created once in `config.py`
- Reused for all files
- Stateless (no instance variables between files)

### Module Dependencies Graph

```
main.py
├── config.py (no deps)
├── traversal.py (os, pathlib)
├── parser.py (tree_sitter)
├── context.py (parser, findings.models)
├── rules/
│   ├── base.py (findings.models)
│   └── [all rules] (base, findings.models, context)
├── findings/
│   ├── models.py (pydantic)
│   └── sarif.py (findings.models)
└── reporting/
    ├── console.py (findings.models, rich)
    └── summary.py (findings.models, rich)
```

### Key Design Principles

1. **Unidirectional Data Flow**: Findings flow from rules → main → reporting (no backflow)
2. **Stateless Rules**: Rules don't store state between files (except within analyze() call)
3. **Context Isolation**: Each file gets its own AnalysisContext
4. **Pure Functions**: Most functions are pure (same input → same output)
5. **Shared Models**: All modules use `Finding` model (single source of truth)
6. **Dependency Injection**: Rules receive context, don't create it
7. **Separation of Concerns**: Rules produce findings, reporting formats them

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
