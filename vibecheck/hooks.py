"""Pre-commit hook support — fast secrets + injection scan before every commit."""

import os
import subprocess
import sys
from pathlib import Path

HOOK_SCRIPT = '''#!/bin/sh
# VibeCheck pre-commit hook — scans staged files for security issues
# Installed by: vibecheck hook install
# Skip with: git commit --no-verify

# Get list of staged files
STAGED=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED" ]; then
    exit 0
fi

# Run vibecheck on staged files only (fast — secrets + high severity)
echo "$STAGED" | while read file; do
    if [ -f "$file" ]; then
        vibecheck scan "$file" --severity high --quiet 2>/dev/null
        if [ $? -eq 1 ]; then
            echo ""
            echo "  VibeCheck: security issues found in staged files."
            echo "  Run 'vibecheck scan .' for details, or 'vibecheck scan . --format fix' for AI fix prompts."
            echo "  Skip with: git commit --no-verify"
            echo ""
            exit 1
        fi
    fi
done
'''


def install_hook(path: str = ".") -> str:
    """Install pre-commit hook in the git repo."""
    root = Path(path).resolve()

    # Find .git directory
    git_dir = root / ".git"
    if not git_dir.exists():
        # Try git rev-parse
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                capture_output=True, text=True, cwd=str(root),
            )
            if result.returncode == 0:
                git_dir = Path(result.stdout.strip())
                if not git_dir.is_absolute():
                    git_dir = root / git_dir
        except FileNotFoundError:
            pass

    if not git_dir.exists():
        return "Error: not a git repository. Run 'git init' first."

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    hook_path = hooks_dir / "pre-commit"

    # Check for existing hook
    if hook_path.exists():
        existing = hook_path.read_text()
        if "vibecheck" in existing.lower():
            return f"VibeCheck hook already installed at {hook_path}"
        # Append to existing hook
        with open(hook_path, "a") as f:
            f.write("\n\n# VibeCheck security scan\n")
            f.write(HOOK_SCRIPT.split("#!/bin/sh\n", 1)[1])
        hook_path.chmod(0o755)
        return f"VibeCheck hook appended to existing pre-commit hook at {hook_path}"
    else:
        hook_path.write_text(HOOK_SCRIPT)
        hook_path.chmod(0o755)
        return f"VibeCheck pre-commit hook installed at {hook_path}"


def uninstall_hook(path: str = ".") -> str:
    """Remove pre-commit hook."""
    root = Path(path).resolve()
    hook_path = root / ".git" / "hooks" / "pre-commit"

    if not hook_path.exists():
        return "No pre-commit hook found."

    content = hook_path.read_text()
    if "vibecheck" not in content.lower():
        return "Pre-commit hook exists but wasn't installed by VibeCheck."

    # If we're the only hook, remove the file
    if "# VibeCheck pre-commit hook" in content and content.strip().startswith("#!/bin/sh"):
        hook_path.unlink()
        return f"VibeCheck pre-commit hook removed from {hook_path}"
    else:
        # Remove just our section
        lines = content.split("\n")
        new_lines = []
        skip = False
        for line in lines:
            if "# VibeCheck" in line:
                skip = True
                continue
            if skip and line.strip() == "":
                skip = False
                continue
            if not skip:
                new_lines.append(line)
        hook_path.write_text("\n".join(new_lines))
        return "VibeCheck section removed from pre-commit hook."
