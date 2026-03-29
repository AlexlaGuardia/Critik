"""Tests for vibecheck explain — check explanations."""

from vibecheck.explain import explain_check, EXPLANATIONS


class TestExplainCheck:
    def test_explains_secrets(self):
        result = explain_check("secrets")
        assert "Hardcoded Secrets" in result
        assert "CRITICAL" in result
        assert "AWS" in result
        assert "Good" in result  # has example with fix

    def test_explains_injection(self):
        result = explain_check("injection")
        assert "SQL" in result
        assert "parameterized" in result

    def test_explains_frameworks_supabase(self):
        result = explain_check("frameworks-supabase")
        assert "service_role" in result
        assert "RLS" in result

    def test_all_checks_have_required_fields(self):
        required = {"title", "severity", "what", "why", "example", "patterns"}
        for name, info in EXPLANATIONS.items():
            missing = required - set(info.keys())
            assert not missing, f"Check '{name}' missing fields: {missing}"

    def test_unknown_check(self):
        result = explain_check("nonexistent")
        assert "not found" in result
        assert "Available:" in result

    def test_partial_match_suggestion(self):
        result = explain_check("supabase")
        assert "Did you mean" in result
        assert "frameworks-supabase" in result

    def test_all_registered_checks_have_explanations(self):
        # Import to trigger registration
        import vibecheck.checks.secrets  # noqa: F401
        import vibecheck.checks.injection  # noqa: F401
        import vibecheck.checks.auth  # noqa: F401
        import vibecheck.checks.config  # noqa: F401
        import vibecheck.checks.dotenv  # noqa: F401
        import vibecheck.checks.frameworks  # noqa: F401
        from vibecheck.checks import get_checks

        check_names = {c["name"] for c in get_checks()}
        explained = set(EXPLANATIONS.keys())

        for name in check_names:
            assert name in explained, f"Check '{name}' has no explanation"
