"""Dedicated secret scanner with high-precision regex set + entropy heuristic."""
from __future__ import annotations
import math
import re
from pathlib import Path
from typing import List

from ..severity import Finding, Severity


SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL, "AWS Access Key ID"),
    (re.compile(r"(?i)aws(.{0,20})?(secret|sk)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"), Severity.CRITICAL, "AWS Secret Access Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), Severity.CRITICAL, "GitHub Personal Access Token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), Severity.CRITICAL, "GitHub Fine-grained PAT"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), Severity.CRITICAL, "OpenAI API Key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), Severity.CRITICAL, "Slack Token"),
    (re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PRIVATE) (PRIVATE )?KEY-----"), Severity.CRITICAL, "Private key material"),
    (re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*=\s*['\"][^'\"\s]{12,}['\"]"), Severity.HIGH, "Possible hardcoded credential"),
]

ASSIGN_RE = re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*=\s*['\"]([^'\"\s]{20,})['\"]")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "reports"}
TEXT_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".sh"}


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class SecretScanner:
    name = "secrets"

    def scan(self, root: Path) -> List[Finding]:
        findings: list[Finding] = []
        for path in root.rglob("*"):
            if not path.is_file() or any(p in SKIP_DIRS for p in path.parts):
                continue
            if path.suffix and path.suffix not in TEXT_EXTS:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), start=1):
                matched = False
                for pat, sev, title in SECRET_PATTERNS:
                    if pat.search(line):
                        findings.append(Finding(
                            scanner=self.name, category="secret", severity=sev,
                            title=title, description=f"Detected in {path}",
                            file=str(path), line=i, snippet=line.strip()[:200],
                        ))
                        matched = True
                        break
                if matched:
                    continue
                m = ASSIGN_RE.search(line)
                if m and _shannon(m.group(2)) > 4.0:
                    findings.append(Finding(
                        scanner=self.name, category="secret", severity=Severity.MEDIUM,
                        title="High-entropy assigned credential",
                        description="High-entropy string assigned to a secret-named variable.",
                        file=str(path), line=i, snippet=line.strip()[:200],
                    ))
        return findings
