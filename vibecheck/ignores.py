"""Ignore patterns — skip directories and files that shouldn't be scanned."""

from pathlib import Path
import fnmatch

DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", "venv", ".venv", "env",
    "dist", "build", ".next", ".tox", ".mypy_cache", ".pytest_cache",
    ".eggs", "*.egg-info", ".nuxt", ".output", "coverage",
    ".terraform", ".serverless",
}

DEFAULT_SKIP_FILES = {
    "*.pyc", "*.pyo", "*.min.js", "*.min.css", "*.map",
    "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "*.wasm", "*.so", "*.dylib", "*.dll",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
    "*.woff", "*.woff2", "*.ttf", "*.eot",
    "*.zip", "*.tar", "*.gz", "*.bz2",
    "*.db", "*.sqlite", "*.sqlite3",
}

SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx",
    ".json", ".yaml", ".yml", ".toml",
    ".env", ".cfg", ".ini", ".conf",
}


def detect_language(path: Path) -> str:
    """Detect language from file extension."""
    ext = path.suffix.lower()
    name = path.name.lower()

    if name.startswith(".env"):
        return "dotenv"

    return {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".toml": "toml",
        ".cfg": "config",
        ".ini": "config",
        ".conf": "config",
    }.get(ext, "unknown")


def load_ignores(root: Path) -> list[str]:
    """Load .vibeignore patterns if present."""
    ignore_file = root / ".vibeignore"
    patterns = []
    if ignore_file.exists():
        for line in ignore_file.read_text().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def should_skip(path: Path, root: Path, custom_ignores: list[str] = None) -> bool:
    """Check if a path should be skipped."""
    rel = path.relative_to(root)
    parts = rel.parts

    # Skip default directories
    for part in parts[:-1]:  # Check parent dirs
        if part in DEFAULT_SKIP_DIRS:
            return True
        for pattern in DEFAULT_SKIP_DIRS:
            if fnmatch.fnmatch(part, pattern):
                return True

    # Skip default file patterns
    for pattern in DEFAULT_SKIP_FILES:
        if fnmatch.fnmatch(path.name, pattern):
            return True

    # Custom ignores
    if custom_ignores:
        rel_str = str(rel)
        for pattern in custom_ignores:
            if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True

    # Must be a supported extension
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS and not path.name.lower().startswith(".env"):
        return True

    return False
