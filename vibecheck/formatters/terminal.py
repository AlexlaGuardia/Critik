"""Colored terminal output formatter."""

from vibecheck.models import ScanResult, Severity

# ANSI color codes
COLORS = {
    Severity.CRITICAL: "\033[91m",  # Red
    Severity.HIGH: "\033[93m",      # Yellow
    Severity.MEDIUM: "\033[33m",    # Orange-ish
    Severity.LOW: "\033[36m",       # Cyan
    Severity.INFO: "\033[90m",      # Gray
}
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def format_terminal(result: ScanResult, no_color: bool = False, quiet: bool = False) -> str:
    """Format scan results for terminal output."""
    lines = []

    if no_color:
        # Strip all ANSI codes
        _c = lambda s, *a: s  # noqa: E731
        _b = lambda s: s  # noqa: E731
        _d = lambda s: s  # noqa: E731
    else:
        _c = lambda s, sev: f"{COLORS.get(sev, '')}{s}{RESET}"  # noqa: E731
        _b = lambda s: f"{BOLD}{s}{RESET}"  # noqa: E731
        _d = lambda s: f"{DIM}{s}{RESET}"  # noqa: E731

    if not quiet:
        from vibecheck import __version__
        lines.append("")
        lines.append(f"  {_b('VibeCheck')} v{__version__} — scanned {result.files_scanned} files")
        lines.append("")

        if not result.findings:
            lines.append(f"  {_c('CLEAN', Severity.INFO)}  No security issues found")
            lines.append("")
        else:
            for finding in result.findings:
                sev_label = finding.severity.value.upper().ljust(8)
                lines.append(f"  {_c(sev_label, finding.severity)}  {_b(finding.check_name)}")
                lines.append(f"  {_d(finding.file_path)}:{finding.line}  {finding.message}")

                if finding.snippet:
                    lines.append(f"  {_d('|')} {finding.line} {_d('|')} {finding.snippet}")

                if finding.fix_hint:
                    lines.append(f"  {_d('+-')} Fix: {finding.fix_hint}")

                lines.append("")

    # Summary line
    lines.append(f"  {'─' * 45}")
    parts = []
    if result.critical_count:
        parts.append(_c(f"{result.critical_count} critical", Severity.CRITICAL))
    if result.high_count:
        parts.append(_c(f"{result.high_count} high", Severity.HIGH))
    if result.medium_count:
        parts.append(_c(f"{result.medium_count} medium", Severity.MEDIUM))
    if result.low_count:
        parts.append(_c(f"{result.low_count} low", Severity.LOW))

    total = len(result.findings)
    duration = f"{result.duration_ms:.0f}ms"

    if total == 0:
        summary = f"  {result.files_scanned} files scanned in {duration} — {_c('clean', Severity.INFO)}"
    else:
        summary = f"  {result.files_scanned} files scanned in {duration} — {total} findings: {', '.join(parts)}"

    lines.append(summary)
    lines.append("")

    return "\n".join(lines)
