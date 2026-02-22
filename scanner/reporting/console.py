# Rich console output: format findings for beautiful terminal display.

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from scanner.findings.models import Finding


# Remediation hints per rule (shown with --verbose)
RULE_REMEDIATIONS: dict[str, str] = {
    "unsafe-functions": (
        "Replace with safe alternatives: gets -> fgets(buf, size, stdin); "
        "strcpy -> strncpy/strlcpy; sprintf -> snprintf; scanf -> use width (e.g. %15s)."
    ),
    "use-after-free": (
        "Set pointer to NULL after free(): free(p); p = NULL; "
        "Or ensure the pointer is never dereferenced after being freed."
    ),
}

# Severity → Rich style
SEVERITY_STYLE = {
    "error": "bold red",
    "warning": "bold yellow",
    "info": "bold blue",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "bold dim",
}

DEFAULT_SEVERITY_STYLE = "bold white"


def _severity_style(severity: str) -> str:
    return SEVERITY_STYLE.get(severity.lower(), DEFAULT_SEVERITY_STYLE)


def _get_remediation(finding: Finding) -> str | None:
    """Return remediation hint for a finding, or None if unknown."""
    return RULE_REMEDIATIONS.get(finding.rule_id)


def print_findings(
    findings: Sequence[Finding],
    analyzed_files: Sequence[Path] | None = None,
    verbose: bool = False,
) -> None:
    """
    Print findings using Rich for a modern, organized terminal UI.
    Groups by file, colors by severity, and shows code snippets when available.
    If verbose, shows remediation hints. If analyzed_files is provided, shows
    a file-by-file summary table (safe vs unsafe).
    """
    console = Console()

    if not findings and not analyzed_files:
        console.print(
            Panel(
                "[green]No issues found.[/green]",
                title="MemLock Analysis",
                border_style="green",
                box=box.ROUNDED,
            )
        )
        return

    # When no findings but we have file list, show success and summary only
    if not findings and analyzed_files:
        _print_file_summary_table([], analyzed_files, console)
        return

    # Group by file path
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        key = str(f.location.path)
        if key not in by_file:
            by_file[key] = []
        by_file[key].append(f)

    # Sort files and findings within each file
    for path in sorted(by_file.keys()):
        file_findings = sorted(by_file[path], key=lambda x: (x.location.line, x.location.column))

        # File header (show shorter path when full path is long)
        rel_path = _shorten_path(path)
        console.print()
        console.print(Panel(
            f"[bold cyan]{rel_path}[/bold cyan]",
            box=box.SIMPLE_HEAD,
            border_style="blue",
            padding=(0, 1),
        ))

        table = Table(
            show_header=True,
            header_style="bold magenta",
            box=box.SIMPLE,
            padding=(0, 1),
            expand=False,
        )
        table.add_column("Line", justify="right", style="dim", width=5)
        table.add_column("Col", justify="right", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Rule", width=22)
        table.add_column("Message", style="white")

        for f in file_findings:
            loc = f.location
            sev_style = _severity_style(f.severity)
            table.add_row(
                str(loc.line),
                str(loc.column),
                Text(f.severity.upper(), style=sev_style),
                Text(f"[{f.rule_id}]", style="dim"),
                f.message,
            )

        console.print(table)

        # Show snippets when available
        snippets = [f for f in file_findings if f.location.snippet]
        if snippets:
            for f in snippets:
                if f.location.snippet:
                    console.print(f"  [dim]|--[/dim] {f.location.snippet.strip()}")
            console.print()

        # Verbose: show remediation hints per unique rule in this file
        if verbose:
            seen_rules: set[str] = set()
            for f in file_findings:
                if f.rule_id not in seen_rules:
                    seen_rules.add(f.rule_id)
                    rem = _get_remediation(f)
                    if rem:
                        console.print(f"  [dim][Fix][/dim] [{f.rule_id}] {rem}")
            if seen_rules:
                console.print()

    # File-by-file summary table
    if analyzed_files:
        _print_file_summary_table(findings, analyzed_files, console)

    # Summary footer
    _print_summary(findings, console)


def _shorten_path(path: str | Path) -> str:
    """Return a shorter display path."""
    path_norm = str(path).replace("\\", "/")
    for marker in ("memlock", "tests"):
        idx = path_norm.lower().find(marker)
        if idx >= 0:
            return path_norm[idx:].lstrip("/")
    return path_norm


def _print_file_summary_table(
    findings: Sequence[Finding],
    analyzed_files: Sequence[Path],
    console: Console,
) -> None:
    """Print a table of safe vs unsafe files."""
    by_path: dict[str, int] = {}
    for f in findings:
        key = str(f.location.path)
        by_path[key] = by_path.get(key, 0) + 1

    safe_files = [p for p in analyzed_files if str(p) not in by_path]
    unsafe_files = [p for p in analyzed_files if str(p) in by_path]

    table = Table(
        title="Files Summary",
        show_header=True,
        header_style="bold cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("File", style="white")
    table.add_column("Status", width=10)
    table.add_column("Findings", justify="right", width=8)

    for p in sorted(unsafe_files, key=str):
        table.add_row(
            _shorten_path(p),
            Text("UNSAFE", style="bold red"),
            str(by_path[str(p)]),
        )
    for p in sorted(safe_files, key=str):
        table.add_row(
            _shorten_path(p),
            Text("OK", style="bold green"),
            "0",
        )

    console.print()
    console.print(Panel(table, border_style="cyan", box=box.ROUNDED))


def _print_summary(findings: Sequence[Finding], console: Console) -> None:
    """Print a compact summary of findings."""
    by_severity: dict[str, int] = {}
    for f in findings:
        s = f.severity.lower()
        by_severity[s] = by_severity.get(s, 0) + 1

    total = len(findings)
    summary_parts = [f"[bold]{total} finding{'s' if total != 1 else ''}[/bold]"]
    for sev in ("error", "warning", "info", "high", "medium", "low"):
        if sev in by_severity:
            summary_parts.append(
                f"[{_severity_style(sev)}]{by_severity[sev]} {sev}[/]"
            )

    console.print()
    console.print(
        Panel(
            " | ".join(summary_parts),
            title="Summary",
            border_style="yellow" if total > 0 else "green",
            box=box.ROUNDED,
        )
    )
