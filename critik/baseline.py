"""Baseline support — save current findings, only report new ones.

Solves the "legacy codebase" onboarding problem: scan a project with
200 existing findings, save the baseline, and future scans only show
findings that weren't in the baseline.

Usage:
  critik scan . --save-baseline    # save current findings to .critik-baseline.json
  critik scan . --baseline         # compare against saved baseline, show only new
"""

import hashlib
import json
from pathlib import Path

from critik.models import Finding, ScanResult

BASELINE_FILE = ".critik-baseline.json"


def finding_fingerprint(finding: Finding) -> str:
    """Generate a stable fingerprint for a finding.

    Uses check_name + relative file path + snippet hash.
    Line numbers change too often — snippet is more stable.
    """
    # Normalize path to relative
    parts = [
        finding.check_name,
        Path(finding.file_path).name,  # just filename, not full path
        hashlib.md5(finding.snippet.strip().encode()).hexdigest()[:12] if finding.snippet else str(finding.line),
    ]
    return "|".join(parts)


def save_baseline(result: ScanResult, root: Path) -> str:
    """Save current findings as the baseline."""
    fingerprints = [finding_fingerprint(f) for f in result.findings]

    data = {
        "version": 1,
        "count": len(fingerprints),
        "fingerprints": sorted(set(fingerprints)),
    }

    path = root / BASELINE_FILE
    path.write_text(json.dumps(data, indent=2) + "\n")

    return f"  Baseline saved: {len(data['fingerprints'])} findings in {BASELINE_FILE}"


def load_baseline(root: Path) -> set[str] | None:
    """Load baseline fingerprints. Returns None if no baseline exists."""
    path = root / BASELINE_FILE
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
        return set(data.get("fingerprints", []))
    except (json.JSONDecodeError, OSError):
        return None


def filter_baseline(result: ScanResult, baseline: set[str]) -> int:
    """Remove findings that match the baseline. Returns count removed."""
    original_count = len(result.findings)

    result.findings = [
        f for f in result.findings
        if finding_fingerprint(f) not in baseline
    ]

    return original_count - len(result.findings)
