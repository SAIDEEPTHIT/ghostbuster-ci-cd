"""JSON, Markdown, and PR-summary report writers."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from ..severity import Finding


SEVERITY_BADGE = {
    "CRITICAL": "🟥 CRITICAL",
    "HIGH": "🟧 HIGH",
    "MEDIUM": "🟨 MEDIUM",
    "LOW": "🟩 LOW",
}


def write_json_report(findings: Iterable[Finding], score: dict, verdict: str, out: Path) -> Path:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "score": score,
        "findings": [f.to_dict() for f in findings],
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    return out


def write_markdown_report(findings: list[Finding], score: dict, verdict: str, threshold: float, out: Path) -> Path:
    lines = []
    badge = "✅ PASS" if verdict == "PASS" else "❌ FAIL"
    lines.append(f"# 👻 GhostBuster CI/CD Report — {badge}")
    lines.append("")
    lines.append(f"- **Risk Score:** `{score['score']}` / 100  (threshold `{threshold}`)")
    lines.append(f"- **Total Findings:** `{score['total_findings']}`")
    lines.append(f"- **Generated:** `{datetime.now(timezone.utc).isoformat()}`")
    lines.append("")
    lines.append("## Severity Breakdown")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = score["severity_counts"].get(sev, 0)
        lines.append(f"- {SEVERITY_BADGE[sev]}: **{n}**")
    lines.append("")
    lines.append("## By Scanner")
    for s, n in sorted(score["by_scanner"].items()):
        lines.append(f"- `{s}`: {n}")
    lines.append("")
    lines.append("## Findings")
    if not findings:
        lines.append("_No findings — clean run._")
    else:
        ordered = sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f.severity.value))
        for f in ordered[:200]:
            loc = f"`{f.file}:{f.line}`" if f.file else "_n/a_"
            lines.append(f"### {SEVERITY_BADGE[f.severity.value]} — {f.title}")
            lines.append(f"- **Scanner:** `{f.scanner}`  •  **Category:** `{f.category}`  •  **Location:** {loc}")
            if f.cve:
                lines.append(f"- **CVE:** `{f.cve}`")
            if f.snippet:
                lines.append(f"- **Snippet:** `{f.snippet}`")
            if f.description:
                lines.append(f"- {f.description}")
            lines.append("")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    return out


def write_pr_summary(findings: list[Finding], score: dict, verdict: str, threshold: float, out: Path) -> Path:
    sc = score["severity_counts"]
    lines = [
        f"## 👻 GhostBuster CI/CD — {'✅ PASS' if verdict == 'PASS' else '❌ FAIL'}",
        "",
        f"**Risk score:** `{score['score']}` / 100 (threshold `{threshold}`)",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🟥 Critical | {sc.get('CRITICAL', 0)} |",
        f"| 🟧 High | {sc.get('HIGH', 0)} |",
        f"| 🟨 Medium | {sc.get('MEDIUM', 0)} |",
        f"| 🟩 Low | {sc.get('LOW', 0)} |",
        "",
        f"_Total findings: **{score['total_findings']}**_",
        "",
        "<details><summary>Top findings</summary>",
        "",
    ]
    ordered = sorted(findings, key=lambda f: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f.severity.value))
    for f in ordered[:15]:
        loc = f"{f.file}:{f.line}" if f.file else "n/a"
        lines.append(f"- **{f.severity.value}** `{f.scanner}` — {f.title} _({loc})_")
    lines.append("")
    lines.append("</details>")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines))
    return out
