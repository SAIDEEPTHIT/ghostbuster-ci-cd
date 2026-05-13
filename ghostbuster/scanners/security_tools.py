"""Wrap real security tools: Bandit, pip-audit, Trivy.

Each runner is best-effort: if the tool is not installed the runner records
an informational finding and continues. This keeps the pipeline reliable
in environments where one tool is unavailable.
"""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
from typing import List

from ..severity import Finding, Severity


def _sev_from_str(s: str) -> Severity:
    s = (s or "").upper()
    if s in {"CRITICAL"}:
        return Severity.CRITICAL
    if s in {"HIGH"}:
        return Severity.HIGH
    if s in {"MEDIUM", "MODERATE"}:
        return Severity.MEDIUM
    return Severity.LOW


class SecurityToolsRunner:
    name = "security_tools"

    def __init__(self, run_bandit=True, run_pip_audit=True, run_trivy=True):
        self.run_bandit = run_bandit
        self.run_pip_audit = run_pip_audit
        self.run_trivy = run_trivy

    def scan(self, root: Path) -> List[Finding]:
        findings: list[Finding] = []
        if self.run_bandit:
            findings.extend(self._bandit(root))
        if self.run_pip_audit:
            findings.extend(self._pip_audit(root))
        if self.run_trivy:
            findings.extend(self._trivy(root))
        return findings

    # -- Bandit ----------------------------------------------------------
    def _bandit(self, root: Path) -> list[Finding]:
        if not shutil.which("bandit"):
            return [self._missing("bandit")]
        try:
            res = subprocess.run(
                ["bandit", "-r", str(root), "-f", "json", "-q",
                 "--exclude", ",".join([str(root / d) for d in [".venv", "venv", "node_modules", "reports"]])],
                capture_output=True, text=True, timeout=180,
            )
        except Exception as e:
            return [Finding("bandit", "tool_error", Severity.LOW, "Bandit failed to run", str(e))]
        try:
            data = json.loads(res.stdout or "{}")
        except json.JSONDecodeError:
            return [Finding("bandit", "tool_error", Severity.LOW, "Bandit output unparseable", res.stderr[:300])]
        out: list[Finding] = []
        for r in data.get("results", []):
            out.append(Finding(
                scanner="bandit",
                category=r.get("test_id", "bandit"),
                severity=_sev_from_str(r.get("issue_severity", "LOW")),
                title=r.get("issue_text", "Bandit finding"),
                description=f"Confidence: {r.get('issue_confidence')}",
                file=r.get("filename"),
                line=r.get("line_number"),
                snippet=(r.get("code") or "").strip()[:200],
                extra={"more_info": r.get("more_info")},
            ))
        return out

    # -- pip-audit -------------------------------------------------------
    def _pip_audit(self, root: Path) -> list[Finding]:
        if not shutil.which("pip-audit"):
            return [self._missing("pip-audit")]
        req = root / "requirements.txt"
        cmd = ["pip-audit", "-f", "json"]
        if req.exists():
            cmd += ["-r", str(req)]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
            data = json.loads(res.stdout or "{}")
        except Exception as e:
            return [Finding("pip-audit", "tool_error", Severity.LOW, "pip-audit failed", str(e))]
        out: list[Finding] = []
        deps = data.get("dependencies", []) if isinstance(data, dict) else data
        for dep in deps:
            for v in dep.get("vulns", []) or []:
                out.append(Finding(
                    scanner="pip-audit",
                    category="cve",
                    severity=Severity.HIGH,
                    title=f"{dep.get('name')} {dep.get('version')}: {v.get('id')}",
                    description=v.get("description", "")[:500],
                    cve=v.get("id"),
                    extra={"fix_versions": v.get("fix_versions", [])},
                ))
        return out

    # -- Trivy -----------------------------------------------------------
    def _trivy(self, root: Path) -> list[Finding]:
        if not shutil.which("trivy"):
            return [self._missing("trivy")]
        try:
            res = subprocess.run(
                ["trivy", "fs", "--quiet", "--format", "json",
                 "--severity", "MEDIUM,HIGH,CRITICAL", str(root)],
                capture_output=True, text=True, timeout=300,
            )
            data = json.loads(res.stdout or "{}")
        except Exception as e:
            return [Finding("trivy", "tool_error", Severity.LOW, "Trivy failed", str(e))]
        out: list[Finding] = []
        for result in data.get("Results", []) or []:
            target = result.get("Target")
            for v in result.get("Vulnerabilities", []) or []:
                out.append(Finding(
                    scanner="trivy",
                    category="cve",
                    severity=_sev_from_str(v.get("Severity", "LOW")),
                    title=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('VulnerabilityID')}",
                    description=(v.get("Title") or v.get("Description") or "")[:500],
                    file=target,
                    cve=v.get("VulnerabilityID"),
                    extra={"fixed_version": v.get("FixedVersion")},
                ))
            for m in result.get("Misconfigurations", []) or []:
                out.append(Finding(
                    scanner="trivy",
                    category="misconfig",
                    severity=_sev_from_str(m.get("Severity", "LOW")),
                    title=m.get("Title", "Trivy misconfiguration"),
                    description=m.get("Description", "")[:500],
                    file=target,
                ))
        return out

    def _missing(self, tool: str) -> Finding:
        return Finding(
            scanner=tool, category="tool_missing", severity=Severity.LOW,
            title=f"{tool} not installed",
            description=f"{tool} was not found on PATH; this scanner was skipped.",
        )
