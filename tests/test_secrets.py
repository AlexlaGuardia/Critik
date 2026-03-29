"""Tests for secret detection."""

from pathlib import Path
from critik.checks.secrets import check_secrets

# Build test keys dynamically to avoid GitHub Push Protection
# flagging these as real secrets in the repo
_STRIPE_LIVE = "sk_" + "live_" + "A" * 24
_STRIPE_TEST = "sk_" + "test_" + "A" * 24


def test_aws_access_key():
    findings = check_secrets(Path("test.py"), 'KEY = "AKIAIOSFODNN7EXAMPLE"', "python")
    assert any(f.check_name == "aws-access-key" for f in findings)


def test_github_pat():
    findings = check_secrets(Path("test.py"), 'TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"', "python")
    assert any(f.check_name == "github-pat" for f in findings)


def test_stripe_live():
    findings = check_secrets(Path("test.py"), f'SK = "{_STRIPE_LIVE}"', "python")
    assert any(f.check_name == "stripe-live-key" for f in findings)
    assert findings[0].severity.value == "critical"


def test_stripe_test_is_medium():
    findings = check_secrets(Path("test.py"), f'SK = "{_STRIPE_TEST}"', "python")
    assert any(f.check_name == "stripe-test-key" for f in findings)
    assert findings[0].severity.value == "medium"


def test_database_url():
    findings = check_secrets(Path("test.py"), 'URL = "postgres://admin:pass@host:5432/db"', "python")
    assert any(f.check_name == "database-url" for f in findings)


def test_slack_token():
    findings = check_secrets(Path("test.py"), 'SLACK = "xoxb-1234567890-abcdefghij"', "python")
    assert any(f.check_name == "slack-token" for f in findings)


def test_private_key():
    findings = check_secrets(Path("test.py"), "-----BEGIN RSA PRIVATE KEY-----", "python")
    assert any(f.check_name == "private-key" for f in findings)


def test_generic_password():
    findings = check_secrets(Path("test.py"), 'password = "supersecret123"', "python")
    assert any(f.check_name == "generic-password" for f in findings)


def test_sendgrid():
    # SG. + 22 chars + . + 43 chars
    findings = check_secrets(Path("t.py"), 'K = "SG.1234567890abcdefghijkl.1234567890abcdefghijklmnopqrstuvwxyz1234567"', "python")
    assert any(f.check_name == "sendgrid-key" for f in findings)


def test_no_false_positive_on_comment():
    findings = check_secrets(Path("test.py"), '# KEY = "AKIAIOSFODNN7EXAMPLE"', "python")
    assert len(findings) == 0


def test_no_false_positive_on_clean_code():
    findings = check_secrets(Path("test.py"), 'name = "hello world"', "python")
    assert len(findings) == 0


def test_works_on_javascript():
    findings = check_secrets(Path("test.js"), f'const key = "{_STRIPE_LIVE}";', "javascript")
    assert any(f.check_name == "stripe-live-key" for f in findings)


def test_line_numbers():
    content = 'line1\nline2\nKEY = "AKIAIOSFODNN7EXAMPLE"\nline4'
    findings = check_secrets(Path("test.py"), content, "python")
    assert findings[0].line == 3
