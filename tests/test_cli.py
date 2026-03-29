"""CLI integration tests."""

import json
import os
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def run_cli(*args) -> tuple[str, int]:
    """Run CLI and capture output + exit code."""
    from vibecheck.cli import main

    captured = StringIO()
    exit_code = 0

    with patch("sys.argv", ["vibecheck"] + list(args)):
        with patch("sys.stdout", captured):
            try:
                main()
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0

    return captured.getvalue(), exit_code


def test_version():
    output, code = run_cli("version")
    from vibecheck import __version__
    assert f"vibecheck {__version__}" in output
    assert code == 0


def test_scan_fixtures_finds_issues():
    output, code = run_cli("scan", str(FIXTURES_DIR))
    assert code == 1  # Should find critical/high issues
    assert "critical" in output.lower() or "CRITICAL" in output


def test_scan_fixtures_json():
    output, code = run_cli("scan", str(FIXTURES_DIR), "--format", "json")
    data = json.loads(output)
    assert data["summary"]["total"] > 0
    assert data["summary"]["critical"] > 0
    assert "findings" in data
    assert len(data["findings"]) > 0


def test_scan_clean_dir(temp_dir):
    (temp_dir / "clean.py").write_text("x = 1\ny = 2\n")
    output, code = run_cli("scan", str(temp_dir))
    assert code == 0


def test_scan_nonexistent():
    _, code = run_cli("scan", "/nonexistent/path")
    assert code == 2


def test_severity_filter():
    output, code = run_cli("scan", str(FIXTURES_DIR), "--severity", "critical", "--format", "json")
    data = json.loads(output)
    for finding in data["findings"]:
        assert finding["severity"] == "critical"


def test_quiet_mode():
    output, code = run_cli("scan", str(FIXTURES_DIR), "--quiet")
    # Should only have summary line, not individual findings
    assert "VibeCheck" not in output  # No header in quiet mode


def test_no_color():
    output, code = run_cli("scan", str(FIXTURES_DIR), "--no-color")
    assert "\033[" not in output  # No ANSI escape codes


@pytest.fixture
def temp_dir():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)
