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
    else:
        print(format_terminal(
            result,
            no_color=args.no_color,
            quiet=args.quiet,
        ))

    sys.exit(result.exit_code)


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
    scan_parser.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal",
                             help="Output format (default: terminal)")
    scan_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"],
                             default="info", help="Minimum severity to report (default: info)")
    scan_parser.add_argument("--ignore", type=str, default=None,
                             help="Additional patterns to ignore (comma-separated)")
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    scan_parser.add_argument("--quiet", action="store_true", help="Only show summary")

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

    commands = {
        "scan": cmd_scan,
        "version": cmd_version,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
