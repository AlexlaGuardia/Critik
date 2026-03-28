"""Config check — insecure defaults, debug mode, CORS issues."""

import re
from pathlib import Path

from vibecheck.checks import check
from vibecheck.models import Finding, Severity

CONFIG_PATTERNS = [
    {
        "name": "debug-enabled",
        "pattern": r"(?i)\bDEBUG\s*=\s*True\b",
        "severity": "medium",
        "message": "Debug mode enabled — may expose sensitive info in production",
        "fix": "Set DEBUG via environment variable, default to False",
        "languages": ["python"],
    },
    {
        "name": "node-dev-mode",
        "pattern": r"""(?i)NODE_ENV\s*[=:]\s*['"]?development['"]?""",
        "severity": "medium",
        "message": "NODE_ENV set to development in source code",
        "fix": "Set NODE_ENV via environment variable at deploy time",
        "languages": ["javascript", "typescript"],
    },
    {
        "name": "cors-wildcard",
        "pattern": r"""(?i)(?:cors|access.control.allow.origin)\s*[(:=]\s*['"]?\*['"]?""",
        "severity": "medium",
        "message": "CORS allows all origins — any website can make requests to your API",
        "fix": "Restrict CORS to specific trusted origins",
        "languages": ["*"],
    },
    {
        "name": "cors-credentials-wildcard",
        "pattern": r"(?i)allow_credentials\s*[=:]\s*True.*origin.*\*|origin.*\*.*allow_credentials\s*[=:]\s*True",
        "severity": "high",
        "message": "CORS with credentials and wildcard origin — browsers block this but it signals misconfiguration",
        "fix": "Never combine credentials: true with origin: *",
        "languages": ["*"],
    },
    {
        "name": "insecure-cookie",
        "pattern": r"(?i)(?:secure|httponly)\s*[=:]\s*(?:false|False)\b",
        "severity": "medium",
        "message": "Cookie security flag disabled",
        "fix": "Set secure: true and httpOnly: true for session cookies",
        "languages": ["*"],
    },
    {
        "name": "verbose-errors",
        "pattern": r"(?i)(?:stack_trace|stacktrace|traceback|show_error_details)\s*[=:]\s*(?:true|True)\b",
        "severity": "low",
        "message": "Verbose error output enabled — may leak internal details",
        "fix": "Disable detailed error output in production",
        "languages": ["*"],
    },
]

_compiled = [(p, re.compile(p["pattern"])) for p in CONFIG_PATTERNS]


@check(
    name="config",
    severity="medium",
    languages=["*"],
    message="Detects insecure configuration defaults",
)
def check_config(file_path: Path, content: str, language: str) -> list[Finding]:
    findings = []
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            continue

        for pattern_def, compiled in _compiled:
            # Filter by language if specified
            if "*" not in pattern_def["languages"] and language not in pattern_def["languages"]:
                continue

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
