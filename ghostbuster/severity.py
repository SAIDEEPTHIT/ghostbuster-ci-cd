"""Severity levels and weights for risk scoring."""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHT = {
    Severity.LOW: 1,
    Severity.MEDIUM: 4,
    Severity.HIGH: 9,
    Severity.CRITICAL: 20,
}


@dataclass
class Finding:
    """A single security/quality finding."""
    scanner: str
    category: str
    severity: Severity
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    snippet: Optional[str] = None
    cve: Optional[str] = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
