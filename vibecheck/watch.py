"""Watch mode — continuous scanning on file changes.

vibecheck watch . — monitors the project for changes and re-scans
modified files. Terminal-first alternative to the VS Code extension.
"""

import os
import sys
import time
from pathlib import Path

from vibecheck.ignores import detect_language, load_ignores, should_skip
from vibecheck.models import Severity
from vibecheck.scanner import Scanner

# Minimum interval between scans of the same file (seconds)
DEBOUNCE_SECONDS = 1.0

# File extensions we care about
WATCHABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".json", ".env", ".yaml", ".yml", ".toml", ".cfg", ".ini",
}


def watch(path: str, min_severity: str = "medium", ai: bool = False):
    """Watch a directory for changes and scan modified files."""
    root = Path(path).resolve()
    if not root.exists():
        print(f"Error: path not found: {root}", file=sys.stderr)
        sys.exit(2)

    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    sev = severity_map.get(min_severity, Severity.MEDIUM)

    custom_ignores = load_ignores(root)

    print(f"\n  Watching {root} for changes (severity >= {min_severity})")
    print(f"  Press Ctrl+C to stop\n")

    # Snapshot file modification times
    mtimes: dict[str, float] = {}
    last_scan: dict[str, float] = {}

    # Initial snapshot
    for file_path in _walk_watchable(root, custom_ignores):
        try:
            mtimes[str(file_path)] = file_path.stat().st_mtime
        except OSError:
            pass

    try:
        while True:
            changed = []

            for file_path in _walk_watchable(root, custom_ignores):
                fstr = str(file_path)
                try:
                    mtime = file_path.stat().st_mtime
                except OSError:
                    continue

                old_mtime = mtimes.get(fstr)
                if old_mtime is None or mtime > old_mtime:
                    # Debounce
                    last = last_scan.get(fstr, 0)
                    if time.monotonic() - last < DEBOUNCE_SECONDS:
                        continue
                    mtimes[fstr] = mtime
                    changed.append(file_path)

            for file_path in changed:
                fstr = str(file_path)
                last_scan[fstr] = time.monotonic()
                _scan_and_report(file_path, root, sev, ai)

            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n  Watch stopped.")


def _walk_watchable(root: Path, custom_ignores: list[str]):
    """Yield watchable files in the directory."""
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in WATCHABLE_EXTENSIONS:
            continue
        if should_skip(path, root, custom_ignores):
            continue
        yield path


def _scan_and_report(file_path: Path, root: Path, min_severity: Severity, ai: bool):
    """Scan a single file and print results inline."""
    from vibecheck.formatters.terminal import COLORS, BOLD, DIM, RESET

    scanner = Scanner(
        path=str(file_path),
        min_severity=min_severity,
        ai=ai,
    )
    result = scanner.scan()

    rel = file_path.relative_to(root)
    now = time.strftime("%H:%M:%S")

    if not result.findings:
        print(f"  {DIM}{now}{RESET} {rel} — {DIM}clean{RESET}")
        return

    count = len(result.findings)
    crits = result.critical_count
    highs = result.high_count

    severity_parts = []
    if crits:
        severity_parts.append(f"{COLORS[Severity.CRITICAL]}{crits} critical{RESET}")
    if highs:
        severity_parts.append(f"{COLORS[Severity.HIGH]}{highs} high{RESET}")
    if result.medium_count:
        severity_parts.append(f"{COLORS[Severity.MEDIUM]}{result.medium_count} medium{RESET}")

    sev_str = ", ".join(severity_parts) if severity_parts else f"{count} findings"

    print(f"  {DIM}{now}{RESET} {BOLD}{rel}{RESET} — {sev_str}")

    for f in result.findings[:5]:  # Show max 5 per file
        sev_label = f.severity.value.upper()[:4]
        color = COLORS.get(f.severity, "")
        print(f"         {color}{sev_label}{RESET} L{f.line}: {f.message}")

    if count > 5:
        print(f"         {DIM}... and {count - 5} more{RESET}")
