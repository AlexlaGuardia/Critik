"""VibeCheck CLI — security scanner for vibe-coded apps."""

import argparse
import sys


def cmd_scan(args):
    """Run security scan."""
    from vibecheck.scanner import Scanner
    from vibecheck.models import Severity
    from vibecheck.formatters.terminal import format_terminal
    from vibecheck.formatters.json_fmt import format_json

    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    min_severity = severity_map.get(args.severity, Severity.INFO)
    extra_ignores = args.ignore.split(",") if args.ignore else None

    try:
        scanner = Scanner(
            path=args.path,
            min_severity=min_severity,
            extra_ignores=extra_ignores,
            ai=getattr(args, "ai", False),
            ai_model=getattr(args, "model", None),
            ai_key=getattr(args, "api_key", None),
            use_baseline=getattr(args, "baseline", False),
            save_baseline=getattr(args, "save_baseline", False),
        )
        result = scanner.scan()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Scanner error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.format == "json":
        print(format_json(result))
    elif args.format == "sarif":
        from vibecheck.formatters.sarif import format_sarif
        print(format_sarif(result))
    elif args.format == "fix":
        from vibecheck.formatters.fix_prompts import format_fix_prompts
        print(format_fix_prompts(result, no_color=args.no_color))
    else:
        print(format_terminal(
            result,
            no_color=args.no_color,
            quiet=args.quiet,
        ))

    # Print baseline save message (outside formatted output)
    if getattr(args, "save_baseline", False) and result.baseline_message:
        print(result.baseline_message, file=sys.stderr)

    sys.exit(result.exit_code)


def cmd_hook(args):
    """Install/uninstall pre-commit hook."""
    from vibecheck.hooks import install_hook, uninstall_hook

    if args.hook_action == "install":
        print(install_hook(args.path if hasattr(args, "path") else "."))
    elif args.hook_action == "uninstall":
        print(uninstall_hook(args.path if hasattr(args, "path") else "."))


def cmd_rules(args):
    """List available checks."""
    from vibecheck.scanner import Scanner  # triggers check registration
    from vibecheck.checks import get_checks

    checks = get_checks()
    print(f"\n  {len(checks)} checks available:\n")
    for c in sorted(checks, key=lambda x: x["name"]):
        sev = c["severity"].value.upper().ljust(8)
        langs = ", ".join(c["languages"])
        print(f"  {sev}  {c['name']:30s}  ({langs})")
    print()


def cmd_init(args):
    """Initialize VibeCheck for this project."""
    from vibecheck.init import run_init
    print(run_init(args.path if hasattr(args, "path") else "."))


def cmd_explain(args):
    """Explain a specific check."""
    from vibecheck.explain import explain_check
    print(explain_check(args.check_name))


def cmd_version(args):
    """Show version."""
    from vibecheck import __version__
    print(f"vibecheck {__version__}")


def main():
    parser = argparse.ArgumentParser(
        prog="vibecheck",
        description="Security scanner for vibe-coded apps",
    )

    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for security issues")
    scan_parser.add_argument("path", nargs="?", default=".", help="Path to scan (default: .)")
    scan_parser.add_argument("--format", choices=["terminal", "json", "sarif", "fix"], default="terminal",
                             help="Output format (default: terminal)")
    scan_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                             default="info", help="Minimum severity to report (default: info)")
    scan_parser.add_argument("--ignore", type=str, default=None,
                             help="Additional patterns to ignore (comma-separated)")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan_parser.add_argument("--quiet", action="store_true", help="Only show summary")
    scan_parser.add_argument("--ai", action="store_true",
                             help="Enable AI-powered analysis (requires GROQ_API_KEY or VIBECHECK_API_KEY)")
    scan_parser.add_argument("--model", type=str, default=None,
                             help="LLM model override (default: llama-3.3-70b-versatile)")
    scan_parser.add_argument("--api-key", type=str, default=None,
                             help="API key (or set VIBECHECK_API_KEY / GROQ_API_KEY env var)")
    scan_parser.add_argument("--baseline", action="store_true",
                             help="Only show findings not in the saved baseline")
    scan_parser.add_argument("--save-baseline", action="store_true",
                             help="Save current findings as the baseline")

    # hook command
    hook_parser = subparsers.add_parser("hook", help="Manage pre-commit hook")
    hook_parser.add_argument("hook_action", choices=["install", "uninstall"], help="Install or uninstall")
    hook_parser.add_argument("path", nargs="?", default=".", help="Repo path (default: .)")

    # init command
    init_parser = subparsers.add_parser("init", help="Detect stack and generate .vibeignore")
    init_parser.add_argument("path", nargs="?", default=".", help="Project path (default: .)")

    # rules command
    subparsers.add_parser("rules", help="List available checks")

    # explain command
    explain_parser = subparsers.add_parser("explain", help="Explain a specific check")
    explain_parser.add_argument("check_name", help="Check name (e.g. secrets, injection, frameworks-supabase)")

    # version command
    subparsers.add_parser("version", help="Show version")

    args = parser.parse_args()

    if args.command is None:
        # Default: scan current directory
        args.command = "scan"
        args.path = "."
        args.format = "terminal"
        args.severity = "info"
        args.ignore = None
        args.no_color = False
        args.quiet = False
        args.ai = False
        args.model = None
        args.api_key = None
        args.baseline = False
        args.save_baseline = False

    commands = {
        "scan": cmd_scan,
        "init": cmd_init,
        "hook": cmd_hook,
        "rules": cmd_rules,
        "explain": cmd_explain,
        "version": cmd_version,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
