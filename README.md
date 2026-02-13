# MemLock - C Static Security Analysis Tool

A Python-based static security analysis tool for detecting vulnerabilities in C source code.

## Project Overview

MemLock is a static analysis tool designed to automatically detect common security vulnerabilities in C source code without executing the program. Built with Python and Tree-sitter, it helps developers identify potentially dangerous patterns early in the development process.

Most real-world C security tools (like Semgrep, Bandit, and Flawfinder) are written in Python, not C. This project follows that same approach, using Python's rich ecosystem for parsing and analysis while targeting C code.

See [project-idea.md](project-idea.md) for detailed project specifications and architecture.

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git

### Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd memlock
   ```

2. Create and switch to the dev branch:
   ```bash
   git checkout -b dev
   git push -u origin dev
   ```

3. Set up a virtual environment:
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Start developing on feature branches:
   ```bash
   git checkout dev
   git pull origin dev
   git checkout -b feature/your-feature-name
   ```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Analyze a directory
cscan analyze ./project

# Filter by severity
cscan analyze ./project --severity medium

# Output format options
cscan analyze ./project --format rich
cscan analyze ./project --format json
```

## Branch Strategy

- **`main`**: Production branch - always contains a working, stable version
- **`dev`**: Development branch - where active development happens
- **`feature/*`**: Feature branches for individual features

### Workflow

1. Create a feature branch from `dev`
2. Make your changes and commit
3. Push and create a Pull Request to `dev`
4. After review and CI checks pass, merge to `dev`
5. When ready for production, create a PR from `dev` to `main`

## CI/CD Pipeline

This repository uses GitHub Actions for continuous integration. The CI pipeline runs on every pull request and includes:

- **Code Linting**: Runs `ruff` and `mypy` for Python code quality
- **Build Check**: Verifies the project installs and imports correctly
- **Code Quality Checks**: Basic code quality validations
- **Security Scan**: Basic security pattern detection

All checks must pass before a PR can be merged to protected branches.

### Running Checks Locally

Install the required tools:

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run linting
ruff check .

# Run type checking
mypy scanner/

# Run tests
pytest tests/

# Run tests for a specific rule only (e.g., buffer_overflow)
pytest tests/test_buffer_overflow.py -v
```

## Project Structure

```
memlock/
├── scanner/
│   ├── main.py                 # Typer CLI entry
│   ├── config.py               # Enabled rules, severity mapping
│   ├── traversal.py            # Walk directories, collect .c files
│   ├── parser.py               # Tree-sitter setup + AST parsing
│   ├── context.py              # Per-file analysis context
│   │
│   ├── findings/
│   │   ├── models.py           # Pydantic Finding, Location, Severity
│   │   └── sarif.py            # Optional SARIF/JSON exporter
│   │
│   ├── rules/
│   │   ├── base.py             # Rule interface
│   │   ├── unsafe_functions.py
│   │   ├── buffer_overflow.py
│   │   ├── memory_management.py
│   │   ├── use_after_free.py
│   │   ├── hardcoded_secrets.py
│   │   ├── integer_overflow.py
│   │   ├── null_checks.py
│   │   └── format_string.py
│   │
│   └── reporting/
│       ├── console.py           # Rich output
│       └── summary.py
│
├── tests/
│   ├── vulnerable/              # Test cases with vulnerabilities
│   └── safe/                    # Test cases without vulnerabilities
│
├── .github/
│   └── workflows/
│       └── ci.yml               # CI/CD pipeline configuration
├── project-idea.md              # Detailed project specifications
├── README.md                    # This file
├── requirements.txt             # Python dependencies
└── .gitignore                   # Git ignore rules
```

## Detected Vulnerabilities

MemLock detects the following vulnerability types:

1. **Unsafe Function Usage** - Dangerous standard library functions (gets, strcpy, sprintf, etc.)
2. **Buffer Overflow Risks** - Array bounds violations and unsafe buffer operations
3. **Memory Management Errors** - Memory leaks, double free, missing free
4. **Use-After-Free** - Basic heuristic detection of freed pointer usage
5. **Hardcoded Secrets** - Passwords, API keys, tokens in source code
6. **Integer Overflow/Underflow** - Arithmetic operations without bounds checks
7. **Missing NULL Checks** - Dereferencing pointers without NULL validation
8. **Format String Vulnerabilities** - Unsafe printf-style functions with user input

## Team Members

- James Smith
- Saint George Aufranc
- Kenny Nguyen

## Development Guidelines

- Write clear, modular Python code
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Handle errors gracefully
- Add docstrings for complex functions
- Test your changes before submitting PRs
- Each rule should only produce Findings - no printing or formatting logic

## Security

This tool is designed to detect security vulnerabilities. As such, it may intentionally use or reference unsafe patterns for testing purposes. Always review the context when security warnings appear.

## License

[To be determined]

## Contributing

1. Create a feature branch from `dev`
2. Make your changes
3. Ensure all CI checks pass
4. Submit a Pull Request
5. Get required approvals
6. Merge after review

---

**Note**: This project is part of CS433 - Computer Security course.
