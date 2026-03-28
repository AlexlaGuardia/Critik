"""Shared test fixtures."""

import os
import tempfile
import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def temp_dir():
    """Create a temp directory for test files."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def temp_file(temp_dir):
    """Helper to create temp files with content."""
    def _create(name: str, content: str) -> Path:
        path = temp_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path
    return _create
