"""Data models for VibeCheck findings."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }[self.value]

    def __lt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


@dataclass
class Finding:
    check_name: str
    severity: Severity
    file_path: str
    line: int
    column: int = 0
    message: str = ""
    snippet: str = ""
    fix_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "check": self.check_name,
            "severity": self.severity.value,
            "file": self.file_path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "snippet": self.snippet,
            "fix": self.fix_hint,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_ms: float = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def exit_code(self) -> int:
        if self.critical_count > 0 or self.high_count > 0:
            return 1
        return 0

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "files_scanned": self.files_scanned,
                "duration_ms": round(self.duration_ms, 1),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "total": len(self.findings),
            },
        }
