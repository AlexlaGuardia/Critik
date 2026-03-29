"""Fix prompt generator — copy-paste prompts for Cursor/Claude/ChatGPT.

This is the distribution hook. ShipSecure charges $8/mo for this. We give it away free.
For each finding, generates an AI-ready prompt that explains the vulnerability
and asks the AI to fix it with the exact file context.
"""

from vibecheck.models import ScanResult, Finding, Severity

COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
CYAN = "\033[36m"


def _generate_prompt(finding: Finding) -> str:
    """Generate a copy-paste prompt for an AI coding tool."""
    parts = [
        f"I have a security vulnerability in `{finding.file_path}` at line {finding.line}.",
        f"",
        f"**Issue:** {finding.message}",
    ]

    if finding.snippet:
        parts.append(f"")
        parts.append(f"**Vulnerable code:**")
        parts.append(f"```")
        parts.append(finding.snippet)
        parts.append(f"```")

    if finding.fix_hint:
        parts.append(f"")
        parts.append(f"**Suggested approach:** {finding.fix_hint}")

    parts.append(f"")
    parts.append(f"Please fix this vulnerability. Show me the corrected code with an explanation of why the original was insecure.")

    return "\n".join(parts)


def format_fix_prompts(result: ScanResult, no_color: bool = False) -> str:
    """Format findings with copy-paste AI fix prompts."""
    lines = []

    if no_color:
        _c = lambda s, *a: s  # noqa: E731
        _b = lambda s: s  # noqa: E731
        _d = lambda s: s  # noqa: E731
        _cy = lambda s: s  # noqa: E731
        box_top = "┌─"
        box_mid = "│ "
        box_bot = "└─"
    else:
        _c = lambda s, sev: f"{COLORS.get(sev, '')}{s}{RESET}"  # noqa: E731
        _b = lambda s: f"{BOLD}{s}{RESET}"  # noqa: E731
        _d = lambda s: f"{DIM}{s}{RESET}"  # noqa: E731
        _cy = lambda s: f"{CYAN}{s}{RESET}"  # noqa: E731
        box_top = f"{DIM}\u250c\u2500{RESET}"
        box_mid = f"{DIM}\u2502{RESET} "
        box_bot = f"{DIM}\u2514\u2500{RESET}"

    from vibecheck import __version__
    lines.append("")
    lines.append(f"  {_b('VibeCheck')} v{__version__} — {_cy('Fix Prompts')}")
    lines.append(f"  {_d('Copy any prompt below into Cursor / Claude / ChatGPT')}")
    lines.append("")

    if not result.findings:
        lines.append(f"  {_c('CLEAN', Severity.INFO)}  No findings to fix")
        lines.append("")
        return "\n".join(lines)

    for i, finding in enumerate(result.findings):
        sev_label = finding.severity.value.upper().ljust(8)
        prompt = _generate_prompt(finding)

        lines.append(f"  {_c(sev_label, finding.severity)}  {_b(finding.check_name)}")
        lines.append(f"  {_d(finding.file_path)}:{finding.line}")
        lines.append("")

        # Prompt in a box
        lines.append(f"  {box_top} {_cy('Prompt for AI:')}")
        for pline in prompt.split("\n"):
            lines.append(f"  {box_mid}{pline}")
        lines.append(f"  {box_bot}")
        lines.append("")

        if i < len(result.findings) - 1:
            lines.append(f"  {_d('─' * 50)}")
            lines.append("")

    # Summary
    lines.append(f"  {'─' * 50}")
    total = len(result.findings)
    lines.append(f"  {total} fix prompt{'s' if total != 1 else ''} generated — paste into your AI tool to fix")
    lines.append("")

    return "\n".join(lines)
