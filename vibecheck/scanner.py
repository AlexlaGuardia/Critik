"""Core scanner — walks files and dispatches checks."""

import time
from pathlib import Path

from vibecheck.models import ScanResult, Severity
from vibecheck.ignores import detect_language, load_ignores, should_skip

# Import check modules to trigger registration
from vibecheck.checks import get_checks  # noqa: E402
import vibecheck.checks.secrets  # noqa: F401
import vibecheck.checks.injection  # noqa: F401
import vibecheck.checks.auth  # noqa: F401
import vibecheck.checks.config  # noqa: F401
import vibecheck.checks.dotenv  # noqa: F401
import vibecheck.checks.frameworks  # noqa: F401


class Scanner:
    def __init__(self, path: str, min_severity: Severity = Severity.INFO,
                 extra_ignores: list[str] = None):
        self.root = Path(path).resolve()
        self.min_severity = min_severity
        self.custom_ignores = load_ignores(self.root)
        if extra_ignores:
            self.custom_ignores.extend(extra_ignores)

    def scan(self) -> ScanResult:
        result = ScanResult()
        start = time.monotonic()

        if not self.root.exists():
            raise FileNotFoundError(f"Path not found: {self.root}")

        if self.root.is_file():
            self._scan_file(self.root, result)
        else:
            for file_path in self._walk_files():
                self._scan_file(file_path, result)

        # Filter by severity
        result.findings = [
            f for f in result.findings
            if f.severity.rank >= self.min_severity.rank
        ]

        # Sort: critical first, then by file
        result.findings.sort(key=lambda f: (-f.severity.rank, f.file_path, f.line))

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    def _scan_file(self, file_path: Path, result: ScanResult):
        """Scan a single file with all applicable checks."""
        try:
            content = file_path.read_text(errors="replace")
        except (PermissionError, OSError):
            return

        # Skip very large files (>1MB)
        if len(content) > 1_000_000:
            return

        language = detect_language(file_path)
        checks = get_checks(language)
        result.files_scanned += 1

        for check_def in checks:
            try:
                findings = check_def["handler"](file_path, content, language)
                result.findings.extend(findings)
            except Exception:
                pass  # Don't crash on individual check failures

    def _walk_files(self):
        """Walk directory tree, yielding scannable files."""
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and not should_skip(path, self.root, self.custom_ignores):
                yield path
