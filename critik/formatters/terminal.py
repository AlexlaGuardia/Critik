"""Colored terminal output formatter."""

from critik.models import ScanResult, Severity

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
GREEN = "\033[92m"
STRIKETHROUGH = "\033[9m"

# AI verdict labels
VERDICT_STYLE = {
    "confirmed": ("CONFIRMED", "\033[91m"),     # Red
    "false_positive": ("FALSE POS", "\033[92m"),  # Green
    "needs_review": ("REVIEW", "\033[93m"),       # Yellow
}


def format_terminal(result: ScanResult, no_color: bool = False, quiet: bool = False) -> str:
    """Format scan results for terminal output."""
    lines = []

    if no_color:
        _c = lambda s, *a: s  # noqa: E731
        _b = lambda s: s  # noqa: E731
        _d = lambda s: s  # noqa: E731
        _raw = lambda s, code: s  # noqa: E731
    else:
        _c = lambda s, sev: f"{COLORS.get(sev, '')}{s}{RESET}"  # noqa: E731
        _b = lambda s: f"{BOLD}{s}{RESET}"  # noqa: E731
        _d = lambda s: f"{DIM}{s}{RESET}"  # noqa: E731
        _raw = lambda s, code: f"{code}{s}{RESET}"  # noqa: E731

    if not quiet:
        from critik import __version__
        lines.append("")
        header = f"  {_b('Critik')} v{__version__} — scanned {result.files_scanned} files"
        if result.ai_enabled:
            header += f"  {_raw('[AI]', GREEN)}"
        lines.append(header)
        lines.append("")

        if not result.findings:
            lines.append(f"  {_c('CLEAN', Severity.INFO)}  No security issues found")
            lines.append("")
        else:
            for finding in result.findings:
                _format_finding(lines, finding, result.ai_enabled, _c, _b, _d, _raw)

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

    # Baseline info
    if result.baseline_filtered:
        lines.append(f"  {_d(f'Baseline: {result.baseline_filtered} known findings hidden')}")
    if result.baseline_message:
        lines.append(f"  {result.baseline_message}")

    # AI summary
    if result.ai_enabled and result.ai_stats:
        stats = result.ai_stats
        ai_parts = []
        if stats.get("confirmed"):
            ai_parts.append(_c(f"{stats['confirmed']} confirmed", Severity.CRITICAL))
        if stats.get("false_positives"):
            ai_parts.append(_raw(f"{stats['false_positives']} false positives", GREEN))
        if stats.get("needs_review"):
            ai_parts.append(_c(f"{stats['needs_review']} needs review", Severity.MEDIUM))
        lines.append(f"  AI analysis: {', '.join(ai_parts)}")

    lines.append("")

    return "\n".join(lines)


def _format_finding(lines, finding, ai_enabled, _c, _b, _d, _raw):
    """Format a single finding with optional AI annotations."""
    is_fp = finding.is_false_positive
    sev = finding.effective_severity if ai_enabled else finding.severity
    sev_label = sev.value.upper().ljust(8)

    if is_fp:
        # Dim the entire finding for false positives
        lines.append(f"  {_d(sev_label)}  {_d(finding.check_name)}")
        lines.append(f"  {_d(finding.file_path)}:{finding.line}  {_d(finding.message)}")
    else:
        lines.append(f"  {_c(sev_label, sev)}  {_b(finding.check_name)}")
        lines.append(f"  {_d(finding.file_path)}:{finding.line}  {finding.message}")

    if finding.snippet and not is_fp:
        lines.append(f"  {_d('|')} {finding.line} {_d('|')} {finding.snippet}")

    # AI verdict badge
    if ai_enabled and finding.ai_verdict:
        verdict_label, verdict_color = VERDICT_STYLE.get(
            finding.ai_verdict, ("UNKNOWN", DIM)
        )
        conf = f" ({finding.ai_confidence}%)" if finding.ai_confidence is not None else ""
        lines.append(f"  {_raw(verdict_label, verdict_color)}{conf}")

        if finding.ai_explanation:
            lines.append(f"  {_d('>')} {finding.ai_explanation}")

        if finding.ai_fix and not is_fp:
            lines.append(f"  {_raw('Fix:', GREEN)} {finding.ai_fix}")
        elif finding.ai_severity and finding.ai_severity != finding.severity.value:
            lines.append(f"  {_d('Severity adjusted:')} {finding.severity.value} -> {finding.ai_severity}")
    elif finding.fix_hint and not is_fp:
        lines.append(f"  {_d('+-')} Fix: {finding.fix_hint}")

    lines.append("")
