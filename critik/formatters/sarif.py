"""SARIF output formatter — compatible with GitHub Code Scanning."""

import json
from critik.models import ScanResult, Severity

SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def format_sarif(result: ScanResult) -> str:
    """Format scan results as SARIF 2.1.0 for GitHub Code Scanning."""
    rules = {}
    results = []

    for finding in result.findings:
        rule_id = finding.check_name

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": finding.message},
                "helpUri": "https://github.com/AlexlaGuardia/critik",
                "properties": {
                    "security-severity": str({
                        Severity.CRITICAL: 9.5,
                        Severity.HIGH: 7.5,
                        Severity.MEDIUM: 5.0,
                        Severity.LOW: 2.5,
                        Severity.INFO: 1.0,
                    }.get(finding.severity, 5.0)),
                },
            }
            if finding.fix_hint:
                rules[rule_id]["help"] = {"text": finding.fix_hint}

        results.append({
            "ruleId": rule_id,
            "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": max(1, finding.column),
                    },
                },
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Critik",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/AlexlaGuardia/critik",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
        }],
    }

    return json.dumps(sarif, indent=2)
