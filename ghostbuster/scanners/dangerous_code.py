"""AST-based detection of dangerous Python calls and patterns."""
from __future__ import annotations
import ast
from pathlib import Path
from typing import List

from ..severity import Finding, Severity


DANGEROUS_CALLS = {
    "eval": (Severity.CRITICAL, "Use of eval() enables arbitrary code execution"),
    "exec": (Severity.CRITICAL, "Use of exec() enables arbitrary code execution"),
    "compile": (Severity.MEDIUM, "Dynamic compile() can be misused"),
    "__import__": (Severity.HIGH, "Dynamic __import__ may load arbitrary modules"),
}

DANGEROUS_ATTR_CALLS = {
    ("os", "system"): (Severity.CRITICAL, "os.system enables shell command injection"),
    ("os", "popen"): (Severity.HIGH, "os.popen can be abused"),
    ("os", "remove"): (Severity.LOW, "Suspicious file deletion"),
    ("os", "unlink"): (Severity.LOW, "Suspicious file deletion"),
    ("shutil", "rmtree"): (Severity.MEDIUM, "Recursive deletion can be destructive"),
    ("os", "chmod"): (Severity.MEDIUM, "chmod usage — verify mode is not world-writable"),
    ("pickle", "loads"): (Severity.CRITICAL, "pickle.loads on untrusted data = RCE"),
    ("pickle", "load"): (Severity.HIGH, "pickle.load is unsafe on untrusted data"),
    ("yaml", "load"): (Severity.HIGH, "yaml.load without SafeLoader is unsafe"),
    ("marshal", "loads"): (Severity.HIGH, "marshal.loads is unsafe deserialization"),
    ("hashlib", "md5"): (Severity.MEDIUM, "MD5 is cryptographically broken"),
    ("hashlib", "sha1"): (Severity.MEDIUM, "SHA1 is cryptographically broken"),
    ("tempfile", "mktemp"): (Severity.HIGH, "tempfile.mktemp is race-prone — use mkstemp"),
}


class DangerousCodeScanner:
    name = "dangerous_code"

    def scan(self, root: Path) -> List[Finding]:
        findings: list[Finding] = []
        skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "reports"}
        for path in root.rglob("*.py"):
            if any(part in skip for part in path.parts):
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(source)
            except (OSError, SyntaxError):
                continue
            findings.extend(self._scan_tree(tree, path, source.splitlines()))
        return findings

    def _scan_tree(self, tree: ast.AST, path: Path, lines: list[str]) -> list[Finding]:
        out: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            sev_msg = self._classify(node)
            if not sev_msg:
                continue
            sev, title, category = sev_msg
            line = node.lineno
            snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            out.append(Finding(
                scanner=self.name,
                category=category,
                severity=sev,
                title=title,
                description=f"Dangerous call detected at {path}:{line}",
                file=str(path),
                line=line,
                snippet=snippet[:200],
            ))
        return out

    def _classify(self, node: ast.Call):
        # bare name calls: eval(...), exec(...)
        if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_CALLS:
            sev, msg = DANGEROUS_CALLS[node.func.id]
            return sev, msg, "dangerous_call"

        # attribute calls: os.system(...), pickle.loads(...)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            key = (node.func.value.id, node.func.attr)
            if key in DANGEROUS_ATTR_CALLS:
                sev, msg = DANGEROUS_ATTR_CALLS[key]
                return sev, msg, "dangerous_call"
            # subprocess with shell=True
            if node.func.value.id == "subprocess" and node.func.attr in {"call", "run", "Popen", "check_call", "check_output"}:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        return Severity.CRITICAL, "subprocess called with shell=True (command injection risk)", "command_injection"
        return None
