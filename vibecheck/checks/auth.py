"""Auth check — detect missing authentication on endpoints."""

import ast
import re
from pathlib import Path

from vibecheck.checks import check
from vibecheck.models import Finding, Severity

FASTAPI_ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete"}
FLASK_ROUTE_DECORATOR = "route"
AUTH_INDICATORS = {"Depends", "Security", "login_required", "auth_required",
                   "permission_required", "jwt_required", "authenticated",
                   "current_user", "get_current_user", "verify_token"}


def _check_python_auth(file_path: Path, content: str) -> list[Finding]:
    """AST-based auth detection for Python (FastAPI, Flask, Django)."""
    findings = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    lines = content.split("\n")

    # Check if file imports any auth-related names
    has_auth_import = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.name for alias in node.names]
            if any(name in AUTH_INDICATORS for name in names):
                has_auth_import = True
                break

    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) and not isinstance(node, ast.AsyncFunctionDef):
            continue

        # Check for route decorators
        is_route = False
        for dec in node.decorator_list:
            dec_name = None
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                dec_name = dec.func.attr
            elif isinstance(dec, ast.Attribute):
                dec_name = dec.attr

            if dec_name in FASTAPI_ROUTE_DECORATORS or dec_name == FLASK_ROUTE_DECORATOR:
                is_route = True
                break

        if not is_route:
            continue

        # Check if function has auth in its parameters (FastAPI Depends pattern)
        has_auth = False
        for default in node.args.defaults:
            if isinstance(default, ast.Call):
                func_name = None
                if isinstance(default.func, ast.Name):
                    func_name = default.func.id
                elif isinstance(default.func, ast.Attribute):
                    func_name = default.func.attr
                if func_name in AUTH_INDICATORS:
                    has_auth = True
                    break

        # Check decorator args for dependencies
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg == "dependencies":
                        has_auth = True
                        break

        # Only flag if the file has auth imports but this route doesn't use them
        if not has_auth and has_auth_import:
            findings.append(Finding(
                check_name="route-no-auth",
                severity=Severity.MEDIUM,
                file_path=str(file_path),
                line=node.lineno,
                column=node.col_offset,
                message=f"Route '{node.name}' has no authentication dependency",
                snippet=lines[node.lineno - 1].rstrip() if node.lineno <= len(lines) else "",
                fix_hint="Add authentication dependency (e.g., Depends(get_current_user))",
            ))

    return findings


_EXPRESS_ROUTE_RE = re.compile(
    r"(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"][^'\"]+['\"]"
)


def _check_js_auth(file_path: Path, content: str) -> list[Finding]:
    """Regex-based auth check for Express routes."""
    findings = []
    lines = content.split("\n")

    # Only check files that look like Express route files
    if "express" not in content.lower() and "router" not in content.lower():
        return findings

    has_auth_middleware = bool(re.search(
        r"(?:authenticate|auth|verify|protect|requireAuth|isAuthenticated|passport)",
        content,
    ))

    if not has_auth_middleware:
        return findings

    for line_num, line in enumerate(lines, 1):
        match = _EXPRESS_ROUTE_RE.search(line)
        if match:
            # Count args between parens to check for middleware
            # Simple heuristic: if only 2 args (path, handler), no middleware
            paren_content = line[match.end():]
            comma_count = 0
            depth = 1
            for ch in paren_content:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif ch == "," and depth == 1:
                    comma_count += 1

            if comma_count < 1:
                findings.append(Finding(
                    check_name="express-no-middleware",
                    severity=Severity.MEDIUM,
                    file_path=str(file_path),
                    line=line_num,
                    column=match.start(),
                    message=f"Express route without auth middleware",
                    snippet=line.rstrip(),
                    fix_hint="Add auth middleware: app.get('/path', authMiddleware, handler)",
                ))

    return findings


@check(
    name="auth",
    severity="medium",
    languages=["python", "javascript", "typescript"],
    message="Detects missing authentication on API endpoints",
)
def check_auth(file_path: Path, content: str, language: str) -> list[Finding]:
    if language == "python":
        return _check_python_auth(file_path, content)
    elif language in ("javascript", "typescript"):
        return _check_js_auth(file_path, content)
    return []
