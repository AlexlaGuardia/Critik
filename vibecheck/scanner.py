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
                 extra_ignores: list[str] = None, ai: bool = False,
                 ai_model: str = None, ai_key: str = None,
                 use_baseline: bool = False, save_baseline: bool = False):
        self.root = Path(path).resolve()
        self.min_severity = min_severity
        self.custom_ignores = load_ignores(self.root)
        if extra_ignores:
            self.custom_ignores.extend(extra_ignores)
        self.ai = ai
        self.ai_model = ai_model
        self.ai_key = ai_key
        self.use_baseline = use_baseline
        self.save_baseline = save_baseline

        # Load custom YAML rules
        from vibecheck.custom_rules import load_custom_rules
        self._custom_rules = load_custom_rules(self.root) or None

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

        # Save baseline if requested (before filtering)
        if self.save_baseline:
            from vibecheck.baseline import save_baseline
            result.baseline_message = save_baseline(result, self.root)

        # Apply baseline filter
        if self.use_baseline:
            from vibecheck.baseline import load_baseline, filter_baseline
            baseline = load_baseline(self.root)
            if baseline is not None:
                removed = filter_baseline(result, baseline)
                result.baseline_filtered = removed
            else:
                result.baseline_message = "  No baseline found. Run: vibecheck scan . --save-baseline"

        # Pass 2: AI analysis
        if self.ai and result.findings:
            self._run_ai_analysis(result)

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    def _run_ai_analysis(self, result: ScanResult):
        """Run AI analysis on findings."""
        import sys
        from vibecheck.ai import AIAnalyzer

        analyzer = AIAnalyzer(api_key=self.ai_key, model=self.ai_model)
        if not analyzer.available:
            print(
                "  No API key found. Set VIBECHECK_API_KEY or GROQ_API_KEY to enable AI analysis.",
                file=sys.stderr,
            )
            return

        files_done = 0
        total_files = len(set(f.file_path for f in result.findings))

        def on_file(file_path, count):
            nonlocal files_done
            files_done += 1
            short = Path(file_path).name
            print(
                f"\r  AI analyzing [{files_done}/{total_files}] {short}...".ljust(60),
                end="", file=sys.stderr, flush=True,
            )

        analyzer.analyze(result.findings, callback=on_file)
        print("\r" + " " * 60 + "\r", end="", file=sys.stderr, flush=True)

        result.ai_enabled = True
        fp_count = sum(1 for f in result.findings if f.is_false_positive)
        confirmed = sum(1 for f in result.findings if f.ai_verdict == "confirmed")
        result.ai_stats = {
            "confirmed": confirmed,
            "false_positives": fp_count,
            "needs_review": len(result.findings) - confirmed - fp_count,
        }

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

        # Custom YAML rules
        if self._custom_rules is not None:
            from vibecheck.custom_rules import scan_with_custom_rules
            try:
                findings = scan_with_custom_rules(file_path, content, language, self._custom_rules)
                result.findings.extend(findings)
            except Exception:
                pass

    def _walk_files(self):
        """Walk directory tree, yielding scannable files."""
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and not should_skip(path, self.root, self.custom_ignores):
                yield path
