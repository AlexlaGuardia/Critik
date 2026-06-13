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

# Tokens that mark a value as a placeholder rather than a real secret.
# `\.{3,}` catches truncation stubs like `sk-...`, `gsk_...`, `AI...` — a real
# key is alphanumeric and never contains three consecutive dots, so this is a
# zero-false-negative signal.
_PLACEHOLDER_TOKENS = re.compile(
    r"(?i)(your[_\-]?|change[_\-]?me|replace[_\-]?me|placeholder|example|sample|insert|"
    r"fill[_\-]?in|todo|fixme|dummy|fake|xxx+|here$|redacted|<[^>]*>|sk-xxx|\.{3,})"
)

# Connection strings that are obviously templates, not leaked creds: loopback/example
# hosts, or literal generic-word credentials (postgres://USER:PASSWORD@..). A real leak
# has a non-loopback host AND non-generic credentials, so these never match it.
_PLACEHOLDER_URL = re.compile(
    r"(?i)://[^/@\s]*:[^/@\s]*@("
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?|host(name)?\b|example\.com|"
    r"your[_\-]?host|db[_\-]?host)"
    r"|://(user(name)?|pass(word)?):(pass(word)?|secret|changeme|x{3,})@"
)

# Connection-string keys carry credentials even though they end in url/uri — keep flagging.
_CONNECTION_KEYS = re.compile(
    r"(?i)(database|db|redis|mongo|mongodb|postgres|postgresql|amqp|rabbitmq|celery|"
    r"broker|cache)_?(url|uri|dsn|connection)?$|_dsn$|connection_string$"
)

# Keys that match the secret-name heuristic by substring but are NOT secrets:
# feature flags, URLs, public IDs, issuers, hosts, etc.
_NON_SECRET_KEY = re.compile(
    r"(?i)(^(enable|disable|use|is|has|allow|require)_|"
    r"_(enabled|disabled|url|uri|endpoint|issuer|id|host|hostname|port|region|zone|"
    r"name|provider|public|publishable|username|user|email|path|dir|mode|env|version|"
    r"timeout|locale|lang|level|count|limit|ttl|expiry|expires|format|type|prefix|"
    r"suffix|domain|origin|scope|audience|realm|bucket|table|schema|channel|topic|"
    r"queue|model|debug|log|theme|color)$)"
)


def _clean_env_value(raw: str) -> str:
    """Extract the literal value from the RHS of a dotenv assignment.

    Strips an unquoted inline ``# comment`` (python-dotenv treats a hash that
    follows whitespace as the start of a comment) and surrounding quotes.
    Quoted values are returned verbatim so a ``#`` *inside* quotes survives.
    """
    v = raw.strip()
    if v[:1] in ("'", '"'):
        quote = v[0]
        end = v.find(quote, 1)
        return v[1:end] if end != -1 else v[1:]
    # Unquoted: a hash preceded by whitespace starts an inline comment.
    m = re.search(r"\s#", v)
    if m:
        v = v[: m.start()].strip()
    return v


def _is_placeholder(value: str) -> bool:
    """True if a value is an obvious placeholder, not a real secret."""
    v = value.strip().strip("'\"").strip()
    if len(v) < 4:
        return True
    # Wrapped placeholders: [VALUE], <VALUE>, {{VALUE}}, ${VALUE}, __VALUE__
    if (v[0] + v[-1]) in ("[]", "<>") \
            or (v.startswith("{{") and v.endswith("}}")) \
            or (v.startswith("${") and v.endswith("}")) \
            or (v.startswith("__") and v.endswith("__")):
        return True
    if _PLACEHOLDER_URL.search(v):
        return True
    return bool(_PLACEHOLDER_TOKENS.search(v))


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

    name_l = file_path.name.lower()
    is_example = any(t in name_l for t in (".example", ".sample", ".template", ".dist"))

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if "=" not in stripped:
            continue

        key, _, value = stripped.partition("=")
        key = key.strip()
        value = _clean_env_value(value)

        if not value or len(value) < 4:
            continue

        if _is_placeholder(value):
            continue

        if SECRET_KEY_NAMES.match(key):
            # Feature flags, URLs, public IDs, issuers etc. match by substring but
            # aren't secrets — unless the key is a credential-bearing connection string.
            if not _CONNECTION_KEYS.search(key) and _NON_SECRET_KEY.search(key):
                continue

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
