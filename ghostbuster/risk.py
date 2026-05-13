"""Weighted risk scoring engine."""
from __future__ import annotations
from collections import Counter, defaultdict
from typing import Iterable

from .severity import Finding, Severity, SEVERITY_WEIGHT


CATEGORY_MULTIPLIER = {
    "hardcoded_secret": 1.5,
    "secret": 1.5,
    "command_injection": 1.4,
    "dangerous_call": 1.2,
    "hallucinated_dependency": 1.2,
    "cve": 1.3,
    "placeholder": 1.0,
    "ai_marker": 1.0,
    "unfinished": 1.0,
    "todo": 0.6,
    "leaked_markdown": 1.0,
    "misconfig": 1.1,
    "tool_missing": 0.0,
    "tool_error": 0.0,
}


def compute_score(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    raw = 0.0
    severity_counts: Counter = Counter()
    category_counts: Counter = Counter()
    by_scanner: defaultdict[str, int] = defaultdict(int)

    for f in findings:
        w = SEVERITY_WEIGHT[f.severity]
        m = CATEGORY_MULTIPLIER.get(f.category, 1.0)
        raw += w * m
        severity_counts[f.severity.value] += 1
        category_counts[f.category] += 1
        by_scanner[f.scanner] += 1

    # Normalize to 0-100 (logarithmic squash so a few CRITICALs don't peg the meter)
    import math
    score = min(100.0, round(20 * math.log1p(raw), 2)) if raw > 0 else 0.0

    return {
        "score": score,
        "raw": round(raw, 2),
        "total_findings": len(findings),
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "by_scanner": dict(by_scanner),
    }


def verdict(score_data: dict, threshold: float) -> str:
    return "PASS" if score_data["score"] < threshold else "FAIL"
