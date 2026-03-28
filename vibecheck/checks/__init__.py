"""Check registry — all security checks register here via @check decorator."""

from vibecheck.models import Severity

_checks: list[dict] = []


def check(name: str, severity: str, languages: list[str], message: str = "", fix_hint: str = ""):
    """Register a security check."""
    def decorator(func):
        _checks.append({
            "name": name,
            "severity": Severity(severity),
            "languages": languages,
            "message": message,
            "fix_hint": fix_hint,
            "handler": func,
        })
        return func
    return decorator


def get_checks(language: str = None) -> list[dict]:
    """Get all checks, optionally filtered by language."""
    if language is None:
        return list(_checks)
    return [c for c in _checks if language in c["languages"] or "*" in c["languages"]]


def get_check_count() -> int:
    return len(_checks)
