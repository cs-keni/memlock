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

## Summary Table

| Enhancement      | Priority | Effort | Notes                    |
|------------------|----------|--------|--------------------------|
| `--json`         | High     | Low    | Straightforward serialization |
| Exit code        | High     | Low    | 1–2 line change          |
| `--severity-min` | Medium   | Medium | Requires severity in config |
| Progress bar     | Medium   | Low    | Rich has built-in support |
| `--explain CWE`  | Lower    | Medium | Need CWE mapping + docs  |

---

## Contributing

When implementing any of these, please:

1. Update this document to mark the enhancement as *Implemented*
2. Add corresponding tests
3. Update the README or CLI help with usage examples
