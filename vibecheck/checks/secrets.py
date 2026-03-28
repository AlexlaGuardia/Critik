"""Secret detection — regex patterns for hardcoded credentials.

Patterns sourced from gitleaks (Apache-2.0) and validated.
"""

import re
from pathlib import Path

from vibecheck.checks import check
from vibecheck.models import Finding, Severity

SECRET_PATTERNS = [
    {
        "name": "aws-access-key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
        "message": "AWS access key detected in source code",
        "fix": "Move to environment variable, never commit AWS keys",
    },
    {
        "name": "aws-secret-key",
        "pattern": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}",
        "severity": "critical",
        "message": "AWS secret access key detected",
        "fix": "Use AWS credentials file or environment variables",
    },
    {
        "name": "github-pat",
        "pattern": r"ghp_[A-Za-z0-9_]{36}",
        "severity": "critical",
        "message": "GitHub personal access token detected",
        "fix": "Use GITHUB_TOKEN environment variable",
    },
    {
        "name": "github-fine-grained",
        "pattern": r"github_pat_[A-Za-z0-9_]{82}",
        "severity": "critical",
        "message": "GitHub fine-grained token detected",
        "fix": "Use GITHUB_TOKEN environment variable",
    },
    {
        "name": "openai-key",
        "pattern": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
        "severity": "critical",
        "message": "OpenAI API key detected",
        "fix": "Use OPENAI_API_KEY environment variable",
    },
    {
        "name": "anthropic-key",
        "pattern": r"sk-ant-[A-Za-z0-9\-_]{90,}",
        "severity": "critical",
        "message": "Anthropic API key detected",
        "fix": "Use ANTHROPIC_API_KEY environment variable",
    },
    {
        "name": "stripe-live-key",
        "pattern": r"sk_live_[A-Za-z0-9]{24,}",
        "severity": "critical",
        "message": "Stripe live secret key detected",
        "fix": "Use STRIPE_SECRET_KEY environment variable. This is a LIVE key.",
    },
    {
        "name": "stripe-test-key",
        "pattern": r"sk_test_[A-Za-z0-9]{24,}",
        "severity": "medium",
        "message": "Stripe test key in source code",
        "fix": "Even test keys should be in environment variables",
    },
    {
        "name": "slack-token",
        "pattern": r"xox[bprs]-[A-Za-z0-9\-]{10,}",
        "severity": "critical",
        "message": "Slack token detected",
        "fix": "Use SLACK_TOKEN environment variable",
    },
    {
        "name": "private-key",
        "pattern": r"-----BEGIN\s+(RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical",
        "message": "Private key detected in source code",
        "fix": "Move to a secure key store, never commit private keys",
    },
    {
        "name": "database-url",
        "pattern": r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@\s]+@[^\s'\"]+",
        "severity": "critical",
        "message": "Database connection string with credentials detected",
        "fix": "Use DATABASE_URL environment variable",
    },
    {
        "name": "sendgrid-key",
        "pattern": r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
        "severity": "critical",
        "message": "SendGrid API key detected",
        "fix": "Use SENDGRID_API_KEY environment variable",
    },
    {
        "name": "telegram-token",
        "pattern": r"[0-9]{8,10}:[A-Za-z0-9_\-]{35}",
        "severity": "high",
        "message": "Telegram bot token detected",
        "fix": "Use TELEGRAM_TOKEN environment variable",
    },
    {
        "name": "generic-password",
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "severity": "high",
        "message": "Hardcoded password detected",
        "fix": "Move to environment variable or secrets manager",
    },
    {
        "name": "generic-api-key",
        "pattern": r"(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*['\"][A-Za-z0-9]{16,}['\"]",
        "severity": "high",
        "message": "Hardcoded API key detected",
        "fix": "Move to environment variable",
    },
    {
        "name": "jwt-token",
        "pattern": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "severity": "high",
        "message": "JWT token detected in source code",
        "fix": "JWTs should never be hardcoded — generate at runtime",
    },
]

_compiled = [(p, re.compile(p["pattern"])) for p in SECRET_PATTERNS]


@check(
    name="secrets",
    severity="critical",
    languages=["*"],
    message="Scans for hardcoded secrets and credentials",
)
def check_secrets(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue

        for pattern_def, compiled in _compiled:
            match = compiled.search(line)
            if match:
                findings.append(Finding(
                    check_name=pattern_def["name"],
                    severity=Severity(pattern_def["severity"]),
                    file_path=str(file_path),
                    line=line_num,
                    column=match.start(),
                    message=pattern_def["message"],
                    snippet=line.rstrip(),
                    fix_hint=pattern_def["fix"],
                ))

    return findings
