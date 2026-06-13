"""Tests for .env / .env.example secret detection.

Guards both directions: placeholder/template values must NOT flag (precision),
and real leaked values MUST flag (recall) — so the false-positive fix can't
silently turn into a false-negative one.

Real-secret literals are assembled at runtime so GitHub Push Protection does
not flag this test file (same trick as test_secrets.py).
"""

from pathlib import Path

from critik.checks.dotenv import _clean_env_value, _is_placeholder, check_dotenv

EXAMPLE = Path(".env.example")
REAL = Path(".env")


def _names(findings):
    return {f.check_name for f in findings}


# --- placeholders / truncation stubs must stay clean (the CData regression) ---

def test_ellipsis_stub_is_placeholder():
    for stub in ("sk-...", "gsk_...", "AI...", "sk-ant-...", "sk-or-..."):
        assert _is_placeholder(stub), f"{stub!r} should read as a placeholder"


def test_example_truncation_stubs_no_findings():
    content = (
        "GEMINI_API_KEY=AI...              # Get free at https://aistudio.google.com\n"
        "GROQ_API_KEY=gsk_...\n"
        "OPENAI_API_KEY=sk-...\n"
        "ANTHROPIC_API_KEY=sk-ant-...\n"
    )
    assert check_dotenv(EXAMPLE, content, "dotenv") == []


def test_inline_comment_is_stripped_from_value():
    assert _clean_env_value("AI...   # Get free at https://aistudio.google.com") == "AI..."
    assert _clean_env_value("changeme # replace before deploy") == "changeme"


def test_quoted_hash_is_preserved():
    # A '#' inside quotes is part of the value, not a comment.
    assert _clean_env_value('"p@ss#word!"') == "p@ss#word!"


# --- real leaked secrets must still flag (no over-correction) ---

def test_real_secret_in_example_still_flags():
    real = "sk-" + "ant-api03-" + "A1b2C3d4" * 6  # realistic length, no ellipsis
    findings = check_dotenv(EXAMPLE, f"ANTHROPIC_API_KEY={real}\n", "dotenv")
    assert "env-example-real-secret" in _names(findings)


def test_real_secret_in_dotenv_flags_high():
    real = "gsk_" + "Z9y8X7w6" * 5
    findings = check_dotenv(REAL, f"GROQ_API_KEY={real}\n", "dotenv")
    assert "env-has-secret" in _names(findings)
    assert any(f.severity.value == "high" for f in findings)


def test_real_secret_with_trailing_comment_still_flags():
    # Stripping the comment must not strip the secret itself.
    real = "sk-" + "live-" + "Q" * 28
    findings = check_dotenv(REAL, f"STRIPE_SECRET_KEY={real}   # prod\n", "dotenv")
    assert "env-has-secret" in _names(findings)
