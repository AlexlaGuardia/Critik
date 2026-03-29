"""Tests for critik init — framework detection and .critikignore generation."""

import json
from pathlib import Path

import pytest

from critik.init import detect_stack, generate_critikignore, run_init


class TestDetectStack:
    def test_empty_directory(self, tmp_path):
        assert detect_stack(tmp_path) == []

    def test_detects_env_file(self, tmp_path):
        (tmp_path / ".env").write_text("KEY=val")
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert ".env file" in names

    def test_detects_nextjs_from_config(self, tmp_path):
        (tmp_path / "next.config.js").write_text("module.exports = {}")
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert "Next.js" in names

    def test_detects_nextjs_from_package_json(self, tmp_path):
        pkg = {"dependencies": {"next": "14.0.0", "react": "18.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert "Next.js" in names
        assert "React" in names
        assert "Node.js" in names

    def test_detects_supabase(self, tmp_path):
        pkg = {"dependencies": {"@supabase/supabase-js": "2.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert "Supabase" in names

    def test_detects_python_fastapi(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text('[project]\nname="app"\ndependencies=["fastapi"]')
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert "Python" in names
        assert "FastAPI" in names

    def test_detects_python_from_requirements(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==3.0\nsqlalchemy==2.0")
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert "Python" in names
        assert "Flask" in names
        assert "SQLAlchemy" in names

    def test_detects_stripe(self, tmp_path):
        pkg = {"dependencies": {"stripe": "12.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert "Stripe" in names

    def test_detects_docker(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12")
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert "Docker" in names

    def test_no_duplicates(self, tmp_path):
        (tmp_path / "next.config.js").write_text("")
        pkg = {"dependencies": {"next": "14.0.0"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert names.count("Next.js") == 1

    def test_handles_bad_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text("not json")
        detected = detect_stack(tmp_path)
        names = [n for n, _ in detected]
        assert "Node.js" in names  # detected from file existence


class TestGenerateVibeignore:
    def test_base_ignores_always_present(self, tmp_path):
        content = generate_critikignore(tmp_path, [])
        assert "node_modules/" in content
        assert "__pycache__/" in content
        assert "tests/fixtures/" in content

    def test_nextjs_ignores_added(self, tmp_path):
        detected = [("Next.js", "frontend")]
        content = generate_critikignore(tmp_path, detected)
        assert ".next/" in content
        assert ".vercel/" in content

    def test_django_ignores_added(self, tmp_path):
        detected = [("Django", "backend")]
        content = generate_critikignore(tmp_path, detected)
        assert "staticfiles/" in content

    def test_rust_ignores_added(self, tmp_path):
        detected = [("Rust", "language")]
        content = generate_critikignore(tmp_path, detected)
        assert "target/" in content


class TestRunInit:
    def test_creates_critikignore(self, tmp_path):
        result = run_init(str(tmp_path))
        assert "Created .critikignore" in result
        assert (tmp_path / ".critikignore").exists()

    def test_skips_existing_critikignore(self, tmp_path):
        (tmp_path / ".critikignore").write_text("custom rules")
        result = run_init(str(tmp_path))
        assert "already exists" in result
        assert (tmp_path / ".critikignore").read_text() == "custom rules"

    def test_shows_detected_stack(self, tmp_path):
        pkg = {"dependencies": {"next": "14", "@supabase/supabase-js": "2"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        result = run_init(str(tmp_path))
        assert "Next.js" in result
        assert "Supabase" in result
        assert "supabase" in result  # check suggestion

    def test_shows_relevant_checks(self, tmp_path):
        pkg = {"dependencies": {"stripe": "12"}}
        (tmp_path / "package.json").write_text(json.dumps(pkg))
        result = run_init(str(tmp_path))
        assert "stripe" in result

    def test_handles_nonexistent_path(self):
        result = run_init("/nonexistent/path")
        assert "Error" in result

    def test_empty_project(self, tmp_path):
        result = run_init(str(tmp_path))
        assert "No frameworks detected" in result
        assert "Created .critikignore" in result
