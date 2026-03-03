# MemLock - Future Enhancements

This document tracks potential CLI and feature improvements for future development. These are not yet implemented but would enhance the tool's usefulness and integration with modern workflows.

---

## CLI Enhancements

### 1. `--json` Output Format

**Description**: Machine-readable JSON output for CI pipelines and tool integration.

**Usage**:
```bash
python -m scanner.main tests/ --format json
# Or: python -m scanner.main tests/ -f json
```

**Benefits**:
- Easy integration with CI/CD (e.g., GitHub Actions, Jenkins)
- Scriptable post-processing (jq, custom parsers)
- Export to other tools or dashboards

**Implementation notes**: Output a JSON array of findings with standard fields (rule_id, message, file, line, column, severity). Consider including file summary in the same structure.

---

### 2. `--severity-min` (Severity Filter)

**Description**: Filter findings by minimum severity threshold.

**Usage**:
```bash
python -m scanner.main tests/ --severity-min warning   # Show warning and above
python -m scanner.main tests/ --severity-min high      # Only high/critical
```

**Benefits**:
- Focus on high-priority issues during tight deadlines
- Reduce noise when low-severity findings are acceptable
- Align with existing severity levels (info, low, warning, medium, high, error)

---

### 3. `--explain CWE-XXX` (CWE Documentation)

**Description**: Show Common Weakness Enumeration (CWE) documentation for a rule or finding.

**Usage**:
```bash
python -m scanner.main --explain CWE-119    # Buffer overflow
python -m scanner.main --explain CWE-416    # Use-after-free
python -m scanner.main --explain CWE-134    # Format string
```

**Example output**:
```
CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
Category: Memory corruption
See: https://cwe.mitre.org/data/definitions/119.html
```

**Benefits**:
- Educational for developers learning security
- Links rules to industry-standard taxonomies
- Helps with security audits and compliance reporting

**Implementation notes**: Maintain a mapping of rule_id -> CWE IDs. Could fetch CWE descriptions from MITRE or ship a minimal static mapping.

---

### 4. Exit Code on Findings

**Description**: Exit with non-zero status when findings are reported, for CI fail-on-issues workflows.

**Usage**:
```bash
python -m scanner.main tests/
# Exit 0 if no findings, exit 1 if any findings
```

**Option**: Add `--strict` or make it default; or add `--no-fail` for CI that should not fail the build.

**Benefits**:
- CI pipelines can fail the build when vulnerabilities are found
- Matches behavior of linters (ESLint, ruff, etc.)

---

### 5. Progress Indicator

**Description**: Show a spinner or progress bar when scanning many files.

**Usage**:
```bash
python -m scanner.main ./large-project/
# Shows: "Scanning... [=====>    ] 12/45 files"
```

**Benefits**:
- Better UX when scanning large codebases
- Confirms the tool is running, not stuck
- Useful for directories with hundreds of .c files

**Implementation notes**: Use Rich's progress bar or a simple spinner. Update on each file completion.

---

## Configuration & Filtering

### 6. Config File Support (`.memlockrc` / `memlock.yaml`)

**Description**: Per-project configuration so teams can customize rules, severity, and exclusions without CLI flags.

**Example** (`.memlockrc` or `memlock.yaml`):
```yaml
# memlock.yaml
rules:
  enable: [unsafe_functions, buffer_overflow, format_string]
  disable: [hardcoded_secrets]  # Too noisy for this project
severity_min: warning
exclude:
  - "**/generated/*.c"
  - "**/legacy/*.c"
```

**Benefits**:
- Consistent settings across team members and CI
- No need to remember long CLI invocations
- Version-controlled project preferences

**Implementation notes**: Use PyYAML or TOML. Search for config in cwd, then parent dirs (like ESLint). Fall back to defaults if not found.

---

### 7. `--exclude` / `.memlockignore` Patterns

**Description**: Exclude specific files or directories from scanning (beyond the built-in `ignore_dirs`).

**Usage**:
```bash
python -m scanner.main ./project --exclude "**/vendor/**" --exclude "**/*_generated.c"
# Or use .memlockignore (gitignore-style patterns)
```

**Benefits**:
- Skip third-party or generated code that shouldn't be analyzed
- Reduce scan time on large repos
- Align with `.gitignore`-style workflows developers already know

**Implementation notes**: Use `pathlib` + `fnmatch` or `pathspec` for glob-style matching. `.memlockignore` in project root, one pattern per line.

---

### 8. Rule Enable/Disable (`--only`, `--skip`)

**Description**: Run only specific rules or skip certain rules for targeted or incremental scans.

**Usage**:
```bash
python -m scanner.main tests/ --only unsafe_functions,buffer_overflow
python -m scanner.main tests/ --skip hardcoded_secrets  # Often noisy
```

**Benefits**:
- Quick checks for a specific vulnerability type
- Work around false-positive-heavy rules until they're tuned
- Useful for security audits focused on one CWE category

---

### 9. Baseline / Suppression File

**Description**: Record known-acceptable findings so they don't clutter output or fail CI. New findings are still reported.

**Usage**:
```bash
# First run: generate baseline from current findings
python -m scanner.main tests/ --output-baseline .memlock-baseline

# Later runs: only report findings NOT in baseline
python -m scanner.main tests/ --baseline .memlock-baseline
```

**Benefits**:
- Adopt MemLock on legacy codebases without fixing everything at once
- CI fails only when *new* issues are introduced
- Common pattern (e.g., ESLint `--cache`, Semgrep baseline)

---

## Output & Reporting

### 10. SARIF Output (Full Implementation)

**Description**: Complete the SARIF exporter in `scanner/findings/sarif.py` for industry-standard tool integration.

**Usage**:
```bash
python -m scanner.main tests/ --format sarif --output report.sarif
```

**Benefits**:
- Import into GitHub Code Scanning, VS Code SARIF viewer, DefectDojo
- Standardized format for security findings
- Better integration with existing security toolchains

**Implementation notes**: SARIF 2.1.0 schema. Map `Finding` → SARIF `Result`. Include `ruleId`, `message`, `locations`, `level`.

---

### 11. HTML Report

**Description**: Generate a standalone HTML report with clickable file links, severity badges, and optional code snippets.

**Usage**:
```bash
python -m scanner.main tests/ --format html --output report.html
```

**Benefits**:
- Shareable with non-technical stakeholders
- Easy to browse findings in a browser
- Can include code context (snippet) per finding if `Location.snippet` is populated

---

### 12. Code Snippets in Findings

**Description**: Populate `Location.snippet` with the offending line(s) of code so reports are self-contained.

**Benefits**:
- Users see the exact code without opening the file
- Improves `--verbose` output and HTML/JSON reports
- Small change in `context.py` or rule base: extract line from source given `line`/`column`

---

## Performance & Scale

### 13. Parallel File Scanning

**Description**: Scan multiple files concurrently using `multiprocessing` or `concurrent.futures`.

**Usage**:
```bash
python -m scanner.main ./large-repo/ --jobs 4
```

**Benefits**:
- Faster scans on multi-core machines
- Important for large codebases (hundreds of .c files)

**Implementation notes**: Tree-sitter parsing is CPU-bound. Use `ProcessPoolExecutor`; be mindful of process spawn overhead for small runs. Consider `--jobs 1` as default for small projects.

---

### 14. `--max-files` Limit

**Description**: Cap the number of files scanned to avoid accidental full-repo scans (e.g., `git clone` + `memlock .` on a huge project).

**Usage**:
```bash
python -m scanner.main . --max-files 500
# If more than 500 .c files: warn and optionally abort or sample
```

**Benefits**:
- Prevents runaway scans on massive directories
- User can explicitly increase limit if intended

---

## Quality of Life

### 15. `--include-headers` Flag

**Description**: Optionally scan `.h` files in addition to `.c` files. `find_source_files` already supports this; expose via CLI.

**Usage**:
```bash
python -m scanner.main ./src/ --include-headers
```

**Benefits**:
- Catch issues in inline functions, macros, or declarations in headers
- Some projects keep security-sensitive logic in headers

---

### 16. Custom Ignore Directories

**Description**: Override or extend `DEFAULT_IGNORE_DIRS` via CLI or config.

**Usage**:
```bash
python -m scanner.main ./project --ignore-dir custom_build --ignore-dir generated
# Or: --no-ignore to scan everything (including tests/, build/)
```

**Benefits**:
- Projects with non-standard layout (e.g., `out/` instead of `build/`)
- Option to scan test code if desired

---

### 17. VSCode / Editor Integration

**Description**: Document or provide a simple script to run MemLock and parse output for the "Problems" panel (grep-like format is already editor-friendly).

**Benefits**:
- Developers see findings inline while coding
- Could provide a minimal extension or task definition

**Implementation notes**: Many editors accept `file:line:col: message` format. A small script or task that runs MemLock and writes to stdout may be enough. Full extension is optional.

---

## LLM-Based Suggestions (Future Consideration)

**Description**: Use an LLM to suggest code fixes for each finding.

**Caveats**:
- **Cost**: Most capable LLMs have usage limits; free tiers may not scale for large codebases.
- **Scale**: Sending entire repos is impractical. A more realistic approach: for each finding, send only the relevant snippet (e.g., 5–10 lines around the issue) plus the rule description. That keeps context small and token usage bounded.
- **Quality**: Suggestions may be wrong or introduce new bugs. Best treated as hints, not auto-applied patches.
- **Offline / Privacy**: Some users cannot send code to external APIs. A fully local model (e.g., Ollama, llama.cpp) could work but adds setup complexity.

**Possible approach** (if pursued later):
- Make it opt-in: `--suggest` flag.
- Only send per-finding snippets, not full files.
- Use a free/local model where possible.
- Clearly label output as "suggested fix (review before applying)".

**Priority**: Low. Static, rule-based remediation hints (e.g., in `--verbose`) are simpler and free. LLM suggestions are a nice-to-have for power users.

---

## Summary Table

| Enhancement        | Priority | Effort | Notes                              |
|--------------------|----------|--------|------------------------------------|
| `--json`           | High     | Low    | Straightforward serialization       |
| Exit code          | High     | Low    | 1–2 line change                    |
| `--severity-min`   | Medium   | Medium | Requires severity in config        |
| Progress bar       | Medium   | Low    | Rich has built-in support          |
| `--explain CWE`    | Lower    | Medium | Need CWE mapping + docs            |
| Config file        | Medium   | Medium | PyYAML/TOML, config discovery      |
| `--exclude`        | Medium   | Medium | Glob patterns, .memlockignore      |
| `--only` / `--skip`| Medium   | Low    | Filter rules by id                 |
| Baseline file      | Medium   | Medium | Diff findings vs baseline         |
| SARIF output       | Medium   | Medium | Complete sarif.py                  |
| HTML report        | Lower    | Medium | Standalone HTML with snippets      |
| Code snippets      | Medium   | Low    | Populate Location.snippet          |
| Parallel scanning  | Medium   | Medium | ProcessPoolExecutor                |
| `--max-files`      | Low      | Low    | Safety cap for large dirs          |
| `--include-headers`| Low      | Low    | Traversal already supports it      |
| Custom ignore dirs | Low      | Low    | Override DEFAULT_IGNORE_DIRS       |
| Editor integration | Lower    | Low    | Doc + optional task/script         |
| LLM suggestions    | Low      | High   | Opt-in, snippet-only, free/local   |

---

## Contributing

When implementing any of these, please:

1. Update this document to mark the enhancement as *Implemented*
2. Add corresponding tests
3. Update the README or CLI help with usage examples
