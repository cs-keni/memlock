# MemLock Test Suite

Test files are organized by **difficulty** (easy → medium → hard) and **safety** (safe vs vulnerable).

## Directory Structure

- **`safe/`** – Code that should pass all rules (no findings)
- **`vulnerable/`** – Code with intentional vulnerabilities (should trigger findings)

## Difficulty Levels

### Easy
- **Single, obvious vulnerability** per file
- Straightforward patterns (e.g., one `gets()` call, one `strcpy` without bounds)
- Minimal control flow

### Medium
- **Multiple related issues** or vulnerability in one code path
- Wrapper functions that propagate unsafe behavior
- Common patterns from real codebases (e.g., unchecked `scanf`, sprintf with user format)

### Hard
- **Enterprise-style complexity**
- Macros that expand to unsafe code
- Nested control flow, linked structures, realloc chains
- Realistic patterns that require deeper analysis

## Test File Naming

- `easy_*_unsafe.c` / `easy_*_safe.c` – Easy difficulty
- `medium_*_unsafe.c` / `medium_*_safe.c` – Medium difficulty  
- `hard_*_unsafe.c` / `hard_*_safe.c` – Hard difficulty

## Rules Covered

| Rule | Easy | Medium | Hard |
|------|------|--------|------|
| buffer-overflow | ✓ | ✓ | ✓ |
| format-string | ✓ | ✓ | ✓ |
| hardcoded-secrets | ✓ | ✓ | ✓ |
| integer-overflow | ✓ | ✓ | ✓ |
| null-checks | ✓ | ✓ | ✓ |
| use-after-free | ✓ | ✓ | ✓ |
| unsafe-functions | ✓ | ✓ | ✓ |

## Running Tests

```bash
python -m scanner.main tests/
```

Vulnerable files should report findings; safe files should report OK.
