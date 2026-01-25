# MemLock - C Static Security Analysis Tool

A static security analysis tool for detecting vulnerabilities in C source code.

## Project Overview

MemLock is a static analysis tool designed to automatically detect common security vulnerabilities in C source code without executing the program. It helps developers identify potentially dangerous patterns early in the development process.

See [proposal.md](proposal.md) for the project proposal and [project-idea.md](project-idea.md) for detailed project specifications.

## Getting Started

### Prerequisites

- GCC compiler
- Make (optional, for build automation)
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

3. Start developing on feature branches:
   ```bash
   git checkout dev
   git pull origin dev
   git checkout -b feature/your-feature-name
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

- **Code Linting**: Runs `cppcheck` and `clang-tidy` for static analysis
- **Build Check**: Verifies the project compiles successfully
- **Code Quality Checks**: Basic code quality validations
- **Security Scan**: Basic security pattern detection

All checks must pass before a PR can be merged to protected branches.

### Running Checks Locally

Install the required tools:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y clang-tidy cppcheck build-essential

# macOS
brew install clang-tidy cppcheck
```

Run checks manually:

```bash
# Static analysis
cppcheck --enable=all .

# Linting
clang-tidy *.c -- -std=c11

# Build
make  # or gcc -o memlock *.c
```

## Project Structure

```
memlock/
├── .github/
│   └── workflows/
│       └── ci.yml              # CI/CD pipeline configuration
├── proposal.md                 # Project proposal
├── project-idea.md             # Detailed project specifications
├── README.md                   # This file
└── .gitignore                  # Git ignore rules
```

## Team Members

- James Smith
- Saint George Aufranc
- Kenny Nguyen

## Development Guidelines

- Write clear, modular C code
- Handle errors gracefully
- Add comments for complex logic
- Follow consistent code style
- Test your changes before submitting PRs

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
