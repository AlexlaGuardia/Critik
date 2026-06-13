"""Auth check — detect missing authentication on endpoints."""

import ast
import re
from pathlib import Path

from critik.checks import check
from critik.models import Finding, Severity

FASTAPI_ROUTE_DECORATORS = {"get", "post", "put", "patch", "delete"}
FLASK_ROUTE_DECORATOR = "route"
AUTH_INDICATORS = {"Depends", "Security", "login_required", "auth_required",
                   "permission_required", "jwt_required", "authenticated",
                   "current_user", "get_current_user", "verify_token"}

# Route-name stems that are public by definition — flagging "login has no auth"
# is noise. Matched as the whole name or a `stem_...` prefix, so register_user,
# health_check, reset_password, login_access_token all qualify.
PUBLIC_ROUTE_STEMS = (
    "login", "logout", "signin", "sign_in", "signup", "sign_up", "register",
    "token", "refresh", "recover", "reset", "forgot", "health", "healthz",
    "ping", "webhook", "root", "index", "docs", "openapi",
)


def _is_public_route(name: str) -> bool:
    name = name.lower()
    return any(name == s or name.startswith(s + "_") for s in PUBLIC_ROUTE_STEMS)


def _node_names(node: ast.AST):
    """Yield every Name.id / Attribute.attr in a subtree (for annotation scans)."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            yield sub.id
        elif isinstance(sub, ast.Attribute):
            yield sub.attr


def _param_has_auth(func_node: ast.AST) -> bool:
    """True if any parameter carries auth via name or annotation.

    Catches the modern FastAPI annotation pattern
    ``current_user: CurrentUser`` / ``user: Annotated[User, Depends(...)]``,
    which lives in the annotation rather than a default value.
    """
    args = func_node.args
    for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
        if arg.arg in AUTH_INDICATORS:
            return True
        if arg.annotation is not None and any(
            n in AUTH_INDICATORS for n in _node_names(arg.annotation)
        ):
            return True
    return False


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

        # Public-by-definition endpoints (login, password reset, health…) don't
        # need auth — flagging them is noise, not signal.
        if _is_public_route(node.name):
            continue

        # Check if function has auth in its parameters. Two patterns:
        #  - default value: def f(user=Depends(get_current_user))
        #  - annotation:    def f(current_user: CurrentUser)   (modern FastAPI)
        has_auth = _param_has_auth(node)
        for default in node.args.defaults:
            if has_auth:
                break
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
