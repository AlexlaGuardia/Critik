"""Tests for the AI analysis layer."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from critik.ai import AIAnalyzer, SYSTEM_PROMPT, MAX_FILE_CHARS
from critik.models import Finding, Severity, ScanResult


def _make_finding(check_name="secrets", severity="critical", file_path="/tmp/test.py",
                  line=10, message="Test finding", snippet="secret = 'abc'"):
    return Finding(
        check_name=check_name,
        severity=Severity(severity),
        file_path=file_path,
        line=line,
        message=message,
        snippet=snippet,
    )


class TestAIAnalyzerInit:
    def test_no_key_not_available(self):
        with patch.dict("os.environ", {}, clear=True):
            a = AIAnalyzer(api_key=None)
            # Manually clear since patch.dict might not remove pre-existing keys
            a.api_key = None
            assert not a.available

    def test_explicit_key(self):
        a = AIAnalyzer(api_key="test-key-123")
        assert a.available

    def test_env_critik_key(self):
        with patch.dict("os.environ", {"CRITIK_API_KEY": "vk-123"}):
            a = AIAnalyzer()
            assert a.available
            assert a.api_key == "vk-123"

    def test_env_groq_key(self):
        with patch.dict("os.environ", {"GROQ_API_KEY": "gsk-123"}, clear=False):
            a = AIAnalyzer()
            # Will pick up CRITIK_API_KEY or GROQ_API_KEY
            assert a.available

    def test_default_model(self):
        a = AIAnalyzer(api_key="test")
        assert a.model == "llama-3.3-70b-versatile"

    def test_custom_model(self):
        a = AIAnalyzer(api_key="test", model="llama-3.1-8b-instant")
        assert a.model == "llama-3.1-8b-instant"


class TestPromptConstruction:
    def test_builds_prompt_with_findings(self):
        a = AIAnalyzer(api_key="test")
        findings = [
            (0, _make_finding(line=10, check_name="aws-access-key",
                              message="AWS key detected", snippet="key = AKIAIOSFODNN7EXAMPLE")),
            (1, _make_finding(line=25, check_name="generic-password",
                              message="Hardcoded password", snippet="pwd = 'hunter2'")),
        ]
        prompt = a._build_prompt("/app/config.py", "import os\n...", findings)

        assert "FILE: /app/config.py" in prompt
        assert "import os" in prompt
        assert "aws-access-key" in prompt
        assert "generic-password" in prompt
        assert "Line 10" in prompt
        assert "Line 25" in prompt
        assert "2 issues flagged" in prompt

    def test_prompt_includes_fix_hints(self):
        a = AIAnalyzer(api_key="test")
        f = _make_finding()
        f.fix_hint = "Use environment variables"
        prompt = a._build_prompt("/test.py", "code", [(0, f)])
        assert "Use environment variables" in prompt


class TestResponseParsing:
    def test_applies_confirmed_verdict(self):
        a = AIAnalyzer(api_key="test")
        findings = [
            (0, _make_finding()),
        ]
        response = {
            "findings": [{
                "index": 0,
                "verdict": "confirmed",
                "confidence": 95,
                "explanation": "This AWS key is real and hardcoded.",
                "severity": None,
                "fix": "Move to os.environ['AWS_KEY']",
            }]
        }
        a._apply_results(response, findings)

        f = findings[0][1]
        assert f.ai_verdict == "confirmed"
        assert f.ai_confidence == 95
        assert f.ai_explanation == "This AWS key is real and hardcoded."
        assert f.ai_fix == "Move to os.environ['AWS_KEY']"
        assert not f.is_false_positive

    def test_applies_false_positive(self):
        a = AIAnalyzer(api_key="test")
        findings = [(0, _make_finding())]
        response = {
            "findings": [{
                "index": 0,
                "verdict": "false_positive",
                "confidence": 88,
                "explanation": "This is a test fixture, not real credentials.",
                "severity": None,
                "fix": None,
            }]
        }
        a._apply_results(response, findings)

        f = findings[0][1]
        assert f.ai_verdict == "false_positive"
        assert f.is_false_positive

    def test_applies_severity_adjustment(self):
        a = AIAnalyzer(api_key="test")
        findings = [(0, _make_finding(severity="high"))]
        response = {
            "findings": [{
                "index": 0,
                "verdict": "confirmed",
                "confidence": 70,
                "explanation": "This is actually critical — the key has admin access.",
                "severity": "critical",
                "fix": "Rotate key immediately.",
            }]
        }
        a._apply_results(response, findings)

        f = findings[0][1]
        assert f.ai_severity == "critical"
        assert f.effective_severity == Severity.CRITICAL
        assert f.severity == Severity.HIGH  # original unchanged

    def test_ignores_invalid_severity(self):
        a = AIAnalyzer(api_key="test")
        findings = [(0, _make_finding())]
        response = {
            "findings": [{
                "index": 0,
                "verdict": "confirmed",
                "confidence": 50,
                "explanation": "test",
                "severity": "super_critical",  # invalid
                "fix": None,
            }]
        }
        a._apply_results(response, findings)
        assert findings[0][1].ai_severity is None

    def test_handles_missing_indices(self):
        a = AIAnalyzer(api_key="test")
        findings = [
            (0, _make_finding(check_name="a")),
            (1, _make_finding(check_name="b")),
        ]
        # LLM only returns verdict for index 0
        response = {
            "findings": [{
                "index": 0,
                "verdict": "confirmed",
                "confidence": 90,
                "explanation": "Real issue.",
                "severity": None,
                "fix": None,
            }]
        }
        a._apply_results(response, findings)
        assert findings[0][1].ai_verdict == "confirmed"
        assert findings[1][1].ai_verdict is None  # untouched

    def test_handles_empty_response(self):
        a = AIAnalyzer(api_key="test")
        findings = [(0, _make_finding())]
        a._apply_results({}, findings)
        assert findings[0][1].ai_verdict is None

    def test_handles_malformed_response(self):
        a = AIAnalyzer(api_key="test")
        findings = [(0, _make_finding())]
        a._apply_results({"findings": [{"garbage": True}]}, findings)
        assert findings[0][1].ai_verdict is None


class TestFileReading:
    def test_reads_small_file(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("print('hello')")
        a = AIAnalyzer(api_key="test")
        content = a._read_file(str(f))
        assert content == "print('hello')"

    def test_truncates_large_file(self, tmp_path):
        f = tmp_path / "big.py"
        f.write_text("x" * (MAX_FILE_CHARS + 5000))
        a = AIAnalyzer(api_key="test")
        content = a._read_file(str(f))
        assert "truncated" in content
        assert len(content) < MAX_FILE_CHARS + 200

    def test_handles_missing_file(self):
        a = AIAnalyzer(api_key="test")
        content = a._read_file("/nonexistent/path.py")
        assert "not readable" in content


class TestAnalyzeIntegration:
    def test_no_findings_returns_empty(self):
        a = AIAnalyzer(api_key="test")
        result = a.analyze([])
        assert result == []

    def test_no_key_returns_findings_unchanged(self):
        a = AIAnalyzer()
        a.api_key = None
        findings = [_make_finding()]
        result = a.analyze(findings)
        assert result[0].ai_verdict is None

    @patch("critik.ai.AIAnalyzer._call_llm")
    def test_full_analysis_flow(self, mock_llm, tmp_path):
        # Create a test file
        test_file = tmp_path / "app.py"
        test_file.write_text("secret = 'AKIAIOSFODNN7EXAMPLE'\nprint(secret)")

        mock_llm.return_value = {
            "findings": [{
                "index": 0,
                "verdict": "confirmed",
                "confidence": 95,
                "explanation": "Hardcoded AWS key in source code.",
                "severity": None,
                "fix": "secret = os.environ['AWS_ACCESS_KEY_ID']",
            }]
        }

        a = AIAnalyzer(api_key="test-key")
        findings = [_make_finding(file_path=str(test_file))]
        result = a.analyze(findings)

        assert result[0].ai_verdict == "confirmed"
        assert result[0].ai_confidence == 95
        mock_llm.assert_called_once()

    @patch("critik.ai.AIAnalyzer._call_llm")
    def test_groups_findings_by_file(self, mock_llm, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("code a")
        f2.write_text("code b")

        mock_llm.return_value = {"findings": []}

        a = AIAnalyzer(api_key="test-key")
        findings = [
            _make_finding(file_path=str(f1), check_name="secret-1"),
            _make_finding(file_path=str(f1), check_name="secret-2"),
            _make_finding(file_path=str(f2), check_name="secret-3"),
        ]
        a.analyze(findings)

        # Should be called twice — once per file
        assert mock_llm.call_count == 2

    @patch("critik.ai.AIAnalyzer._call_llm")
    def test_callback_called_per_file(self, mock_llm, tmp_path):
        f1 = tmp_path / "a.py"
        f1.write_text("code")
        mock_llm.return_value = {"findings": []}

        callback = MagicMock()
        a = AIAnalyzer(api_key="test-key")
        a.analyze([_make_finding(file_path=str(f1))], callback=callback)
        callback.assert_called_once()

    @patch("critik.ai.AIAnalyzer._call_llm")
    def test_llm_failure_doesnt_crash(self, mock_llm, tmp_path):
        f = tmp_path / "a.py"
        f.write_text("code")
        mock_llm.side_effect = Exception("API error")

        a = AIAnalyzer(api_key="test-key")
        findings = [_make_finding(file_path=str(f))]
        result = a.analyze(findings)
        # Findings returned unchanged
        assert result[0].ai_verdict is None


class TestModelProperties:
    def test_effective_severity_no_ai(self):
        f = _make_finding(severity="high")
        assert f.effective_severity == Severity.HIGH

    def test_effective_severity_with_ai(self):
        f = _make_finding(severity="high")
        f.ai_severity = "critical"
        assert f.effective_severity == Severity.CRITICAL

    def test_effective_severity_invalid_ai(self):
        f = _make_finding(severity="high")
        f.ai_severity = "bogus"
        assert f.effective_severity == Severity.HIGH

    def test_to_dict_without_ai(self):
        f = _make_finding()
        d = f.to_dict()
        assert "ai" not in d

    def test_to_dict_with_ai(self):
        f = _make_finding()
        f.ai_verdict = "confirmed"
        f.ai_confidence = 90
        f.ai_explanation = "Real issue"
        f.ai_fix = "fix it"
        f.ai_severity = "critical"
        d = f.to_dict()
        assert d["ai"]["verdict"] == "confirmed"
        assert d["ai"]["confidence"] == 90

    def test_scan_result_to_dict_with_ai(self):
        r = ScanResult(ai_enabled=True, ai_stats={"confirmed": 3, "false_positives": 1})
        d = r.to_dict()
        assert d["ai"]["confirmed"] == 3

    def test_scan_result_to_dict_without_ai(self):
        r = ScanResult()
        d = r.to_dict()
        assert "ai" not in d
