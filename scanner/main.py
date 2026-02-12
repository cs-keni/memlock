from __future__ import annotations

"""
Typer CLI entry point and orchestration of the analysis pipeline.

This is a minimal, working CLI that:
- Accepts a file or directory path
- Finds .c files (using traversal.find_c_files for directories)
- Builds a FileContext for each file
- Runs all enabled rules from config.py
- Prints findings to stdout in a simple \"file:line:col: [rule] message\" format

As more pieces are implemented (richer reporting, SARIF, more rules), this
module can be extended without changing rule implementations.
"""

import logging
from pathlib import Path
from typing import List, Sequence

import typer

from scanner.config import Config, get_default_config, get_enabled_rules
from scanner.context import create_context
from scanner.findings.models import Finding
from scanner.traversal import find_c_files

logger = logging.getLogger(__name__)

app = typer.Typer(help="MemLock - C static security analysis tool for C source files.")


def _collect_c_files(target: Path) -> List[Path]:
    """
    Resolve a target path into a list of .c files to analyze.

    - If target is a .c file, return [target]
    - If target is a directory, use traversal.find_c_files()
    - Otherwise, exit with an error.
    """
    if target.is_file():
        if target.suffix.lower() != ".c":
            raise typer.BadParameter(f"Target file must have .c extension, got: {target}")
        return [target]

    if target.is_dir():
        files = find_c_files(target)
        if not files:
            logger.warning("No .c files found under %s", target)
        return files

    raise typer.BadParameter(f"Target path is neither a file nor a directory: {target}")


def _print_findings(findings: Sequence[Finding]) -> None:
    """Print findings in a simple, grep-like format."""
    if not findings:
        typer.echo("No findings.")
        return

    for f in findings:
        loc = f.location
        typer.echo(
            f"{loc.path}:{loc.line}:{loc.column}: {f.severity.upper()} "
            f"[{f.rule_id}] {f.message}"
        )


@app.command()
def analyze(
    target: Path = typer.Argument(
        ...,
        exists=True,
        readable=True,
        resolve_path=True,
        help="C file or directory to analyze.",
    ),
) -> None:
    """
    Analyze a single C file or all .c files under a directory.

    Uses the rules registered in config.get_default_config().
    """
    config: Config = get_default_config()
    files = _collect_c_files(target)

    all_findings: List[Finding] = []
    rules = list(get_enabled_rules(config))

    if not rules:
        typer.echo("No rules are enabled in the current configuration.")
        raise typer.Exit(code=1)

    for path in files:
        ctx = create_context(path)
        if ctx is None:
            # File could not be read; error already logged in create_context
            continue
        for rule in rules:
            try:
                rule_findings = rule.run(ctx, config)
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("Rule %s failed on %s: %s", rule.id, path, exc)
                continue
            # Rule.run() returns list[Any], but in practice these are Finding
            all_findings.extend(rule_findings)  # type: ignore[arg-type]

    _print_findings(all_findings)


def main() -> None:
    """Entry point for `python -m scanner.main`."""
    app()


if __name__ == "__main__":
    main()

# Typer CLI entry point and main orchestration of the analysis pipeline.

def placeholder() -> None:
    """Placeholder function to keep module tracked."""
    return None
