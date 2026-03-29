"""Custom YAML rules engine — community-contributed security patterns.

Rule format (.critik/rules/*.yml or .critik/rules/*.yaml):

  id: supabase-rls-disabled
  severity: critical
  languages: [javascript, typescript]
  message: "Supabase table has RLS disabled"
  pattern: "rpc\\("
  fix: "Enable RLS: ALTER TABLE $TABLE ENABLE ROW LEVEL SECURITY"

Pattern matching uses Python regex against each line of the file.
Rules are loaded once and registered alongside built-in checks.
"""

import re
import sys
from pathlib import Path
from typing import Optional

from critik.checks import check
from critik.models import Finding, Severity

# Try to import yaml — it's optional
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

RULES_DIR = ".critik/rules"

# Cache for loaded custom rules
_custom_rules: list[dict] = []
_rules_loaded = False


def _parse_rule(data: dict, source_file: str) -> Optional[dict]:
    """Validate and parse a single rule definition."""
    required = {"id", "severity", "pattern", "message"}
    missing = required - set(data.keys())
    if missing:
        print(f"  Warning: rule in {source_file} missing fields: {missing}", file=sys.stderr)
        return None

    sev = data["severity"].lower()
    if sev not in ("critical", "high", "medium", "low", "info"):
        print(f"  Warning: rule '{data['id']}' has invalid severity: {sev}", file=sys.stderr)
        return None

    try:
        compiled = re.compile(data["pattern"])
    except re.error as e:
        print(f"  Warning: rule '{data['id']}' has invalid regex: {e}", file=sys.stderr)
        return None

    return {
        "id": data["id"],
        "severity": Severity(sev),
        "languages": data.get("languages", ["*"]),
        "message": data["message"],
        "fix": data.get("fix", ""),
        "pattern": compiled,
        "source": source_file,
    }


def load_custom_rules(root: Path) -> list[dict]:
    """Load custom rules from .critik/rules/ directory."""
    global _custom_rules, _rules_loaded

    if _rules_loaded:
        return _custom_rules

    _rules_loaded = True
    rules_dir = root / RULES_DIR

    if not rules_dir.exists():
        return _custom_rules

    if not HAS_YAML:
        print("  Warning: PyYAML not installed. Custom rules require: pip install pyyaml", file=sys.stderr)
        return _custom_rules

    for rule_file in sorted(rules_dir.glob("*.y*ml")):
        try:
            content = rule_file.read_text()
            # Support multiple rules per file (YAML document separator ---)
            docs = list(yaml.safe_load_all(content))
            for doc in docs:
                if doc is None:
                    continue
                # Handle both single rule and list of rules
                if isinstance(doc, list):
                    for item in doc:
                        rule = _parse_rule(item, str(rule_file))
                        if rule:
                            _custom_rules.append(rule)
                elif isinstance(doc, dict):
                    rule = _parse_rule(doc, str(rule_file))
                    if rule:
                        _custom_rules.append(rule)
        except Exception as e:
            print(f"  Warning: failed to load {rule_file}: {e}", file=sys.stderr)

    return _custom_rules


def scan_with_custom_rules(file_path: Path, content: str, language: str,
                           rules: list[dict]) -> list[Finding]:
    """Run custom rules against a file."""
    findings = []
    lines = content.split("\n")

    for rule in rules:
        # Check language filter
        if "*" not in rule["languages"] and language not in rule["languages"]:
            continue

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue

            match = rule["pattern"].search(line)
            if match:
                findings.append(Finding(
                    check_name=rule["id"],
                    severity=rule["severity"],
                    file_path=str(file_path),
                    line=line_num,
                    column=match.start(),
                    message=rule["message"],
                    snippet=line.rstrip(),
                    fix_hint=rule["fix"],
                ))

    return findings


def reset_custom_rules():
    """Reset loaded rules (for testing)."""
    global _custom_rules, _rules_loaded
    _custom_rules = []
    _rules_loaded = False


def validate_rule_file(path: str) -> str:
    """Validate a YAML rule file and return formatted result."""
    if not HAS_YAML:
        return "Error: PyYAML not installed. Run: pip install pyyaml"

    rule_path = Path(path)
    if not rule_path.exists():
        return f"Error: file not found: {path}"

    try:
        content = rule_path.read_text()
        docs = list(yaml.safe_load_all(content))
    except Exception as e:
        return f"Error: invalid YAML: {e}"

    lines = [f"\n  Validating {rule_path.name}:\n"]
    valid = 0
    invalid = 0

    for doc in docs:
        if doc is None:
            continue
        items = doc if isinstance(doc, list) else [doc]
        for item in items:
            rule = _parse_rule(item, str(rule_path))
            if rule:
                lines.append(f"  OK  {rule['id']} [{rule['severity'].value}] — {rule['message'][:60]}")
                valid += 1
            else:
                lines.append(f"  ERR {item.get('id', '(no id)')}")
                invalid += 1

    lines.append(f"\n  {valid} valid, {invalid} invalid\n")
    return "\n".join(lines)


def install_rule_file(source: str, root: str = ".") -> str:
    """Copy a rule file into .critik/rules/."""
    source_path = Path(source)
    if not source_path.exists():
        return f"Error: file not found: {source}"

    target_dir = Path(root).resolve() / RULES_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    target = target_dir / source_path.name
    if target.exists():
        return f"Rule file already exists: {target}"

    target.write_text(source_path.read_text())
    return f"Installed: {target}"
