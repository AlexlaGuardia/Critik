"""Data models for Critik findings."""

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
    # AI analysis fields (populated when --ai is used)
    ai_verdict: Optional[str] = None  # "confirmed", "false_positive", "needs_review"
    ai_confidence: Optional[int] = None  # 0-100
    ai_explanation: Optional[str] = None
    ai_fix: Optional[str] = None
    ai_severity: Optional[str] = None  # adjusted severity, None = no change

    @property
    def effective_severity(self) -> "Severity":
        """Return AI-adjusted severity if available, otherwise original."""
        if self.ai_severity:
            try:
                return Severity(self.ai_severity)
            except ValueError:
                pass
        return self.severity

    @property
    def is_false_positive(self) -> bool:
        return self.ai_verdict == "false_positive"

    def to_dict(self) -> dict:
        d = {
            "check": self.check_name,
            "severity": self.severity.value,
            "file": self.file_path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "snippet": self.snippet,
            "fix": self.fix_hint,
        }
        if self.ai_verdict is not None:
            d["ai"] = {
                "verdict": self.ai_verdict,
                "confidence": self.ai_confidence,
                "explanation": self.ai_explanation,
                "fix": self.ai_fix,
                "severity": self.ai_severity,
            }
        return d


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    duration_ms: float = 0
    ai_enabled: bool = False
    ai_stats: dict = field(default_factory=dict)
    baseline_filtered: int = 0
    baseline_message: str = ""

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
        d = {
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
        if self.ai_enabled:
            d["ai"] = self.ai_stats
        return d
