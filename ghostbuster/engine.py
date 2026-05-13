"""Validator engine — orchestrates all scanners and produces a unified result."""
from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

from .scanners import (
    AIPatternScanner, HallucinatedDependencyScanner, DangerousCodeScanner,
    SecretScanner, SecurityToolsRunner,
)
from .severity import Finding
from .risk import compute_score, verdict as compute_verdict


@dataclass
class EngineConfig:
    target: Path
    threshold: float = 40.0
    enable_ai_patterns: bool = True
    enable_hallucinated_deps: bool = True
    enable_dangerous_code: bool = True
    enable_secrets: bool = True
    enable_security_tools: bool = True
    check_pypi: bool = True


@dataclass
class EngineResult:
    findings: List[Finding]
    score: dict
    verdict: str
    threshold: float


class GhostBusterEngine:
    """Top-level engine. Run all enabled scanners and aggregate."""

    def __init__(self, config: EngineConfig):
        self.config = config
        self.scanners = []
        if config.enable_ai_patterns:
            self.scanners.append(AIPatternScanner())
        if config.enable_hallucinated_deps:
            self.scanners.append(HallucinatedDependencyScanner(check_pypi=config.check_pypi))
        if config.enable_dangerous_code:
            self.scanners.append(DangerousCodeScanner())
        if config.enable_secrets:
            self.scanners.append(SecretScanner())
        if config.enable_security_tools:
            self.scanners.append(SecurityToolsRunner())

    def run(self) -> EngineResult:
        all_findings: list[Finding] = []
        for sc in self.scanners:
            try:
                all_findings.extend(sc.scan(self.config.target))
            except Exception as e:  # never let one scanner kill the run
                from .severity import Severity
                all_findings.append(Finding(
                    scanner=sc.name, category="scanner_error", severity=Severity.LOW,
                    title=f"{sc.name} crashed", description=str(e),
                ))
        score = compute_score(all_findings)
        v = compute_verdict(score, self.config.threshold)
        return EngineResult(all_findings, score, v, self.config.threshold)
