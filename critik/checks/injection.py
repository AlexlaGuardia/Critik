"""Injection detection — SQL injection, command injection, eval/exec."""

import ast
import re
from pathlib import Path

from critik.checks import check
from critik.models import Finding, Severity


def _check_python_injection(file_path: Path, content: str) -> list[Finding]:
    """AST-based injection detection for Python files."""
    findings = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    lines = content.split("\n")

    for node in ast.walk(tree):
        # eval() / exec() usage
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in ("eval", "exec"):
                findings.append(Finding(
                    check_name=f"{func_name}-usage",
                    severity=Severity.HIGH,
                    file_path=str(file_path),
                    line=node.lineno,
                    column=node.col_offset,
                    message=f"Use of {func_name}() — can execute arbitrary code",
                    snippet=lines[node.lineno - 1].rstrip() if node.lineno <= len(lines) else "",
                    fix_hint=f"Avoid {func_name}(). Use ast.literal_eval() for data parsing, or refactor to avoid dynamic execution.",
                ))

            # os.system()
            if func_name == "system" and isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    findings.append(Finding(
                        check_name="os-system",
                        severity=Severity.MEDIUM,
                        file_path=str(file_path),
                        line=node.lineno,
                        column=node.col_offset,
                        message="os.system() is vulnerable to command injection",
                        snippet=lines[node.lineno - 1].rstrip() if node.lineno <= len(lines) else "",
                        fix_hint="Use subprocess.run() with a list of arguments (no shell=True)",
                    ))

            # subprocess with shell=True
            if func_name in ("call", "run", "Popen", "check_output"):
                if isinstance(node.func, ast.Attribute):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(Finding(
                                check_name="subprocess-shell",
                                severity=Severity.HIGH,
                                file_path=str(file_path),
                                line=node.lineno,
                                column=node.col_offset,
                                message="subprocess with shell=True is vulnerable to command injection",
                                snippet=lines[node.lineno - 1].rstrip() if node.lineno <= len(lines) else "",
                                fix_hint="Use a list of arguments instead of a shell string",
                            ))

        # SQL injection via f-string or string concat in .execute()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "execute" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.JoinedStr):  # f-string
                    findings.append(Finding(
                        check_name="sql-fstring",
                        severity=Severity.HIGH,
                        file_path=str(file_path),
                        line=node.lineno,
                        column=node.col_offset,
                        message="SQL injection via f-string in execute()",
                        snippet=lines[node.lineno - 1].rstrip() if node.lineno <= len(lines) else "",
                        fix_hint="Use parameterized query: execute(\"SELECT ... WHERE id = ?\", (id,))",
                    ))
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
                    findings.append(Finding(
                        check_name="sql-string-concat",
                        severity=Severity.HIGH,
                        file_path=str(file_path),
                        line=node.lineno,
                        column=node.col_offset,
                        message="SQL injection via string concatenation in execute()",
                        snippet=lines[node.lineno - 1].rstrip() if node.lineno <= len(lines) else "",
                        fix_hint="Use parameterized query: execute(\"SELECT ... WHERE id = ?\", (id,))",
                    ))

    return findings


_JS_EVAL_RE = re.compile(r"\beval\s*\(")
_JS_INNERHTML_RE = re.compile(r"dangerouslySetInnerHTML")
_JS_DOC_WRITE_RE = re.compile(r"document\.write\s*\(")


def _check_js_injection(file_path: Path, content: str) -> list[Finding]:
    """Regex-based injection detection for JS/TS files."""
    findings = []
    lines = content.split("\n")

    patterns = [
        (_JS_EVAL_RE, "js-eval", Severity.HIGH,
         "eval() can execute arbitrary code", "Avoid eval(). Use JSON.parse() for data, or refactor."),
        (_JS_INNERHTML_RE, "dangerous-innerhtml", Severity.HIGH,
         "dangerouslySetInnerHTML enables XSS attacks",
         "Sanitize HTML with DOMPurify, or use React's default escaping"),
        (_JS_DOC_WRITE_RE, "document-write", Severity.MEDIUM,
         "document.write() can be exploited for XSS",
         "Use DOM manipulation methods instead (createElement, textContent)"),
    ]

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        for regex, name, severity, message, fix in patterns:
            match = regex.search(line)
            if match:
                findings.append(Finding(
                    check_name=name,
                    severity=severity,
                    file_path=str(file_path),
                    line=line_num,
                    column=match.start(),
                    message=message,
                    snippet=line.rstrip(),
                    fix_hint=fix,
                ))

    return findings


@check(
    name="injection",
    severity="high",
    languages=["python", "javascript", "typescript"],
    message="Detects SQL injection, command injection, eval/exec, XSS vectors",
)
def check_injection(file_path: Path, content: str, language: str) -> list[Finding]:
    if language == "python":
        return _check_python_injection(file_path, content)
    elif language in ("javascript", "typescript"):
        return _check_js_injection(file_path, content)
    return []
