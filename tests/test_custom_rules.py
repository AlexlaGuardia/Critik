"""Tests for custom YAML rules engine."""

import pytest
from pathlib import Path

from vibecheck.custom_rules import (
    load_custom_rules,
    scan_with_custom_rules,
    validate_rule_file,
    install_rule_file,
    reset_custom_rules,
    _parse_rule,
)
from vibecheck.models import Severity

# Check if PyYAML is available
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@pytest.fixture(autouse=True)
def reset():
    """Reset custom rules between tests."""
    reset_custom_rules()
    yield
    reset_custom_rules()


def _write_rule(tmp_path, filename="test.yml", content=None):
    """Helper to write a rule file."""
    rules_dir = tmp_path / ".vibecheck" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    rule_file = rules_dir / filename
    if content is None:
        content = (
            "id: test-rule\n"
            "severity: high\n"
            "languages: [javascript]\n"
            "message: 'Test rule matched'\n"
            "pattern: 'dangerousPattern'\n"
            "fix: 'Remove dangerousPattern'\n"
        )
    rule_file.write_text(content)
    return rule_file


@pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
class TestParseRule:
    def test_valid_rule(self):
        data = {
            "id": "test",
            "severity": "high",
            "pattern": "foo",
            "message": "Found foo",
        }
        rule = _parse_rule(data, "test.yml")
        assert rule is not None
        assert rule["id"] == "test"
        assert rule["severity"] == Severity.HIGH

    def test_missing_required_field(self):
        data = {"id": "test", "severity": "high"}  # missing pattern, message
        rule = _parse_rule(data, "test.yml")
        assert rule is None

    def test_invalid_severity(self):
        data = {"id": "test", "severity": "super", "pattern": "x", "message": "y"}
        rule = _parse_rule(data, "test.yml")
        assert rule is None

    def test_invalid_regex(self):
        data = {"id": "test", "severity": "high", "pattern": "[invalid", "message": "y"}
        rule = _parse_rule(data, "test.yml")
        assert rule is None

    def test_default_languages(self):
        data = {"id": "test", "severity": "high", "pattern": "x", "message": "y"}
        rule = _parse_rule(data, "test.yml")
        assert rule["languages"] == ["*"]


@pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
class TestLoadCustomRules:
    def test_no_rules_dir(self, tmp_path):
        rules = load_custom_rules(tmp_path)
        assert rules == []

    def test_loads_rules_from_dir(self, tmp_path):
        _write_rule(tmp_path)
        rules = load_custom_rules(tmp_path)
        assert len(rules) == 1
        assert rules[0]["id"] == "test-rule"

    def test_loads_multi_doc_yaml(self, tmp_path):
        content = (
            "id: rule-a\nseverity: high\npattern: 'aaa'\nmessage: 'Found A'\n"
            "---\n"
            "id: rule-b\nseverity: medium\npattern: 'bbb'\nmessage: 'Found B'\n"
        )
        _write_rule(tmp_path, content=content)
        rules = load_custom_rules(tmp_path)
        assert len(rules) == 2


@pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
class TestScanWithCustomRules:
    def test_matches_pattern(self, tmp_path):
        rules = [{
            "id": "test-check",
            "severity": Severity.HIGH,
            "languages": ["javascript"],
            "message": "Found bad pattern",
            "fix": "Fix it",
            "pattern": __import__("re").compile("dangerousCall"),
            "source": "test.yml",
        }]
        findings = scan_with_custom_rules(
            tmp_path / "app.js",
            "const x = dangerousCall(input)",
            "javascript",
            rules,
        )
        assert len(findings) == 1
        assert findings[0].check_name == "test-check"
        assert findings[0].line == 1

    def test_respects_language_filter(self, tmp_path):
        rules = [{
            "id": "js-only",
            "severity": Severity.HIGH,
            "languages": ["javascript"],
            "message": "JS only",
            "fix": "",
            "pattern": __import__("re").compile("badThing"),
            "source": "test.yml",
        }]
        # Should not match Python files
        findings = scan_with_custom_rules(
            tmp_path / "app.py",
            "badThing()",
            "python",
            rules,
        )
        assert len(findings) == 0

    def test_wildcard_language(self, tmp_path):
        rules = [{
            "id": "any-lang",
            "severity": Severity.MEDIUM,
            "languages": ["*"],
            "message": "Any language",
            "fix": "",
            "pattern": __import__("re").compile("TODO_SECURITY"),
            "source": "test.yml",
        }]
        findings = scan_with_custom_rules(
            tmp_path / "app.py",
            "# TODO_SECURITY: fix this\nreal_code()",
            "python",
            rules,
        )
        # Should skip comments
        assert len(findings) == 0

    def test_no_match(self, tmp_path):
        rules = [{
            "id": "no-match",
            "severity": Severity.HIGH,
            "languages": ["*"],
            "message": "Never matches",
            "fix": "",
            "pattern": __import__("re").compile("NEVER_IN_CODE_12345"),
            "source": "test.yml",
        }]
        findings = scan_with_custom_rules(
            tmp_path / "app.py",
            "safe_code()",
            "python",
            rules,
        )
        assert len(findings) == 0


@pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
class TestValidateRuleFile:
    def test_valid_file(self, tmp_path):
        f = tmp_path / "test.yml"
        f.write_text("id: test\nseverity: high\npattern: 'x'\nmessage: 'y'\n")
        result = validate_rule_file(str(f))
        assert "1 valid" in result
        assert "0 invalid" in result

    def test_invalid_file(self, tmp_path):
        f = tmp_path / "bad.yml"
        f.write_text("id: test\n")  # missing fields
        result = validate_rule_file(str(f))
        assert "1 invalid" in result

    def test_missing_file(self):
        result = validate_rule_file("/nonexistent.yml")
        assert "Error" in result


@pytest.mark.skipif(not HAS_YAML, reason="PyYAML not installed")
class TestInstallRuleFile:
    def test_installs_to_rules_dir(self, tmp_path):
        source = tmp_path / "my_rules.yml"
        source.write_text("id: test\nseverity: high\npattern: 'x'\nmessage: 'y'\n")

        project = tmp_path / "project"
        project.mkdir()

        result = install_rule_file(str(source), str(project))
        assert "Installed" in result
        assert (project / ".vibecheck" / "rules" / "my_rules.yml").exists()

    def test_rejects_duplicate(self, tmp_path):
        source = tmp_path / "rules.yml"
        source.write_text("id: test\nseverity: high\npattern: 'x'\nmessage: 'y'\n")

        project = tmp_path / "project"
        (project / ".vibecheck" / "rules").mkdir(parents=True)
        (project / ".vibecheck" / "rules" / "rules.yml").write_text("existing")

        result = install_rule_file(str(source), str(project))
        assert "already exists" in result

    def test_missing_source(self):
        result = install_rule_file("/nonexistent.yml")
        assert "Error" in result
