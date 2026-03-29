"""Dotenv check — .env file exposure and leaked secrets."""

import re
from pathlib import Path

from critik.checks import check
from critik.models import Finding, Severity

# Keys that commonly hold secrets
SECRET_KEY_NAMES = re.compile(
    r"(?i)^(.*(?:secret|password|passwd|pwd|token|key|auth|credential|private|api[_\-]?key)"
    r"|.*(?:DATABASE_URL|REDIS_URL|MONGO_URI|AWS_SECRET|STRIPE_SECRET|OPENAI|ANTHROPIC))"
)

# Values that look like real secrets (not placeholders)
PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)^(your[_\-]|change[_\-]?me|replace[_\-]?me|xxx|todo|fixme|placeholder|example|"
    r"<.*>|\.\.\.|CHANGE_ME|YOUR_KEY_HERE|INSERT_HERE|FILL_IN|REPLACE_THIS|test|dummy|fake|sample)$"
)


@check(
    name="dotenv-secrets",
    severity="high",
    languages=["dotenv"],
    message="Detects real secrets in .env files",
)
def check_dotenv(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")

    # Check if .env is gitignored
    git_root = _find_git_root(file_path)
    if git_root and file_path.name == ".env":
        gitignore_path = git_root / ".gitignore"
        if gitignore_path.exists():
            gitignore_content = gitignore_path.read_text()
            if ".env" not in gitignore_content:
                findings.append(Finding(
                    check_name="env-not-gitignored",
                    severity=Severity.CRITICAL,
                    file_path=str(file_path),
                    line=1,
                    message=".env file is not listed in .gitignore — secrets will be committed",
                    snippet="",
                    fix_hint="Add '.env' to your .gitignore file immediately",
                ))
        else:
            findings.append(Finding(
                check_name="env-no-gitignore",
                severity=Severity.HIGH,
                file_path=str(file_path),
                line=1,
                message="No .gitignore file found — .env file may be committed",
                snippet="",
                fix_hint="Create a .gitignore and add '.env' to it",
            ))

    is_example = file_path.name in (".env.example", ".env.sample", ".env.template")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if "=" not in stripped:
            continue

        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip("'\"")

        if not value or len(value) < 4:
            continue

        if PLACEHOLDER_PATTERNS.match(value):
            continue

        if SECRET_KEY_NAMES.match(key):
            severity = Severity.MEDIUM if is_example else Severity.HIGH
            check_name = "env-example-real-secret" if is_example else "env-has-secret"
            msg = (
                f"Real-looking secret value for '{key}' in example file"
                if is_example
                else f"Secret value for '{key}' in .env file"
            )
            findings.append(Finding(
                check_name=check_name,
                severity=severity,
                file_path=str(file_path),
                line=line_num,
                message=msg,
                snippet=f"{key}=****",  # Don't show actual value
                fix_hint="Use placeholder values in .env.example files" if is_example
                else "Ensure .env is in .gitignore and never committed",
            ))

    return findings


def _find_git_root(path: Path) -> Path | None:
    """Walk up to find .git directory."""
    current = path.parent
    for _ in range(10):
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None
