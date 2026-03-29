"""Tests for injection detection."""

from pathlib import Path
from critik.checks.injection import check_injection


def test_sql_fstring():
    code = '''
def get_user(uid):
    db.execute(f"SELECT * FROM users WHERE id = {uid}")
'''
    findings = check_injection(Path("test.py"), code, "python")
    assert any(f.check_name == "sql-fstring" for f in findings)


def test_sql_string_concat():
    code = '''
def search(q):
    db.execute("SELECT * FROM items WHERE name = '" + q + "'")
'''
    findings = check_injection(Path("test.py"), code, "python")
    assert any(f.check_name == "sql-string-concat" for f in findings)


def test_eval_usage():
    code = '''
def process(data):
    result = eval(data)
'''
    findings = check_injection(Path("test.py"), code, "python")
    assert any(f.check_name == "eval-usage" for f in findings)


def test_exec_usage():
    code = '''
exec(user_code)
'''
    findings = check_injection(Path("test.py"), code, "python")
    assert any(f.check_name == "exec-usage" for f in findings)


def test_subprocess_shell():
    code = '''
import subprocess
subprocess.call(cmd, shell=True)
'''
    findings = check_injection(Path("test.py"), code, "python")
    assert any(f.check_name == "subprocess-shell" for f in findings)


def test_os_system():
    code = '''
import os
os.system(command)
'''
    findings = check_injection(Path("test.py"), code, "python")
    assert any(f.check_name == "os-system" for f in findings)


def test_js_eval():
    findings = check_injection(Path("test.js"), "const x = eval(input);", "javascript")
    assert any(f.check_name == "js-eval" for f in findings)


def test_dangerous_innerhtml():
    code = '<div dangerouslySetInnerHTML={{__html: data}} />'
    findings = check_injection(Path("test.tsx"), code, "typescript")
    assert any(f.check_name == "dangerous-innerhtml" for f in findings)


def test_safe_parameterized_query():
    code = '''
def get_user(uid):
    db.execute("SELECT * FROM users WHERE id = ?", (uid,))
'''
    findings = check_injection(Path("test.py"), code, "python")
    assert len(findings) == 0


def test_safe_python_no_issues():
    code = '''
import json
data = json.loads(text)
'''
    findings = check_injection(Path("test.py"), code, "python")
    assert len(findings) == 0
