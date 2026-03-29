"""Tests for critik baseline — save and filter known findings."""

import json
from pathlib import Path

import pytest

from critik.baseline import (
    finding_fingerprint,
    save_baseline,
    load_baseline,
    filter_baseline,
    BASELINE_FILE,
)
from critik.models import Finding, Severity, ScanResult


def _make_finding(check_name="test-check", file_path="/app/test.py",
                  line=10, snippet="vulnerable_code()"):
    return Finding(
        check_name=check_name,
        severity=Severity.HIGH,
        file_path=file_path,
        line=line,
        snippet=snippet,
    )


class TestFingerprint:
    def test_same_finding_same_fingerprint(self):
        f1 = _make_finding()
        f2 = _make_finding()
        assert finding_fingerprint(f1) == finding_fingerprint(f2)

    def test_different_check_different_fingerprint(self):
        f1 = _make_finding(check_name="a")
        f2 = _make_finding(check_name="b")
        assert finding_fingerprint(f1) != finding_fingerprint(f2)

    def test_different_snippet_different_fingerprint(self):
        f1 = _make_finding(snippet="code_a()")
        f2 = _make_finding(snippet="code_b()")
        assert finding_fingerprint(f1) != finding_fingerprint(f2)

    def test_line_change_same_fingerprint(self):
        """Line numbers change often — fingerprint uses snippet instead."""
        f1 = _make_finding(line=10)
        f2 = _make_finding(line=25)
        assert finding_fingerprint(f1) == finding_fingerprint(f2)

    def test_different_directory_same_filename(self):
        """Uses just filename, not full path — robust to refactoring."""
        f1 = _make_finding(file_path="/app/src/test.py")
        f2 = _make_finding(file_path="/app/lib/test.py")
        assert finding_fingerprint(f1) == finding_fingerprint(f2)


class TestSaveBaseline:
    def test_creates_file(self, tmp_path):
        result = ScanResult(findings=[_make_finding()])
        msg = save_baseline(result, tmp_path)
        assert (tmp_path / BASELINE_FILE).exists()
        assert "1 findings" in msg

    def test_file_is_valid_json(self, tmp_path):
        result = ScanResult(findings=[_make_finding(), _make_finding(check_name="other")])
        save_baseline(result, tmp_path)
        data = json.loads((tmp_path / BASELINE_FILE).read_text())
        assert data["version"] == 1
        assert data["count"] == 2
        assert len(data["fingerprints"]) == 2

    def test_deduplicates_fingerprints(self, tmp_path):
        f1 = _make_finding()
        f2 = _make_finding()  # identical
        result = ScanResult(findings=[f1, f2])
        save_baseline(result, tmp_path)
        data = json.loads((tmp_path / BASELINE_FILE).read_text())
        assert len(data["fingerprints"]) == 1  # deduplicated


class TestLoadBaseline:
    def test_returns_none_when_missing(self, tmp_path):
        assert load_baseline(tmp_path) is None

    def test_loads_saved_baseline(self, tmp_path):
        result = ScanResult(findings=[_make_finding()])
        save_baseline(result, tmp_path)
        baseline = load_baseline(tmp_path)
        assert baseline is not None
        assert len(baseline) == 1

    def test_handles_corrupt_file(self, tmp_path):
        (tmp_path / BASELINE_FILE).write_text("not json")
        assert load_baseline(tmp_path) is None


class TestFilterBaseline:
    def test_filters_known_findings(self, tmp_path):
        known = _make_finding(check_name="known")
        new = _make_finding(check_name="new", snippet="new_vuln()")

        # Save baseline with known finding
        baseline_result = ScanResult(findings=[known])
        save_baseline(baseline_result, tmp_path)
        baseline = load_baseline(tmp_path)

        # Scan result has both
        scan_result = ScanResult(findings=[known, new])
        removed = filter_baseline(scan_result, baseline)

        assert removed == 1
        assert len(scan_result.findings) == 1
        assert scan_result.findings[0].check_name == "new"

    def test_keeps_all_when_no_match(self, tmp_path):
        baseline = {finding_fingerprint(_make_finding(check_name="old"))}
        result = ScanResult(findings=[_make_finding(check_name="new")])
        removed = filter_baseline(result, baseline)
        assert removed == 0
        assert len(result.findings) == 1

    def test_removes_all_when_all_match(self, tmp_path):
        f = _make_finding()
        baseline = {finding_fingerprint(f)}
        result = ScanResult(findings=[f])
        removed = filter_baseline(result, baseline)
        assert removed == 1
        assert len(result.findings) == 0
