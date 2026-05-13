"""Detect hallucinated / non-existent Python dependencies and modules.

Strategy:
  1. Parse imports from .py files using AST.
  2. Filter out stdlib modules (sys.stdlib_module_names).
  3. For each remaining top-level package, check:
       a. Is it importable locally?
       b. Does it exist on PyPI? (HEAD request, cached)
  4. Anything that is neither importable nor on PyPI is flagged HIGH.
  5. Known suspicious / commonly-hallucinated names are flagged CRITICAL.
"""
from __future__ import annotations
import ast
import sys
import json
import urllib.request
import urllib.error
from pathlib import Path
from typing import Iterable, List, Set
from importlib.util import find_spec

from ..severity import Finding, Severity

# Names commonly hallucinated by LLMs (do not exist on PyPI or are confusing).
KNOWN_HALLUCINATED: Set[str] = {
    "openaiwrapper", "gpt_helper", "auto_security", "pyhackerkit",
    "ai_security_lib", "hallucinated_lib", "fake_requests", "supersecure",
    "magicimport", "neuralcrypto",
}

# Heuristic: package name lookalikes (typosquat candidates).
LOOKALIKES = {
    "reqeusts": "requests",
    "beautifulsoup": "beautifulsoup4",
    "urllib3-ext": "urllib3",
    "numpyy": "numpy",
    "panda": "pandas",
    "tensorflow-gpu-cpu": "tensorflow",
}

PYPI_URL = "https://pypi.org/pypi/{name}/json"


class HallucinatedDependencyScanner:
    name = "hallucinated_deps"

    def __init__(self, check_pypi: bool = True, timeout: float = 4.0):
        self.check_pypi = check_pypi
        self.timeout = timeout
        self._pypi_cache: dict[str, bool] = {}

    def scan(self, root: Path) -> List[Finding]:
        imports = self._collect_imports(root)
        stdlib = set(getattr(sys, "stdlib_module_names", set()))
        findings: list[Finding] = []

        for top, locations in imports.items():
            if top in stdlib or top.startswith("_"):
                continue
            # Local package?
            if (root / top).exists() or (root / f"{top}.py").exists():
                continue

            sev: Severity | None = None
            title = ""
            desc = ""

            if top.lower() in KNOWN_HALLUCINATED:
                sev = Severity.CRITICAL
                title = f"Known hallucinated package '{top}'"
                desc = "This package name is commonly fabricated by LLMs and does not exist."
            elif top.lower() in LOOKALIKES:
                sev = Severity.HIGH
                title = f"Typosquat-style import '{top}'"
                desc = f"Did you mean '{LOOKALIKES[top.lower()]}'?"
            else:
                installed = find_spec(top) is not None
                on_pypi = self._exists_on_pypi(top) if (self.check_pypi and not installed) else installed
                if not installed and not on_pypi:
                    sev = Severity.HIGH
                    title = f"Hallucinated / unknown dependency '{top}'"
                    desc = "Module is not installed locally and not found on PyPI."

            if sev is not None:
                file, line = locations[0]
                findings.append(Finding(
                    scanner=self.name,
                    category="hallucinated_dependency",
                    severity=sev,
                    title=title,
                    description=desc,
                    file=str(file),
                    line=line,
                    snippet=f"import {top}",
                    extra={"all_locations": [(str(f), l) for f, l in locations]},
                ))
        return findings

    def _collect_imports(self, root: Path) -> dict[str, list[tuple[Path, int]]]:
        imports: dict[str, list[tuple[Path, int]]] = {}
        skip = {".git", "node_modules", ".venv", "venv", "__pycache__", "reports"}
        for path in root.rglob("*.py"):
            if any(part in skip for part in path.parts):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        imports.setdefault(top, []).append((path, node.lineno))
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    top = node.module.split(".")[0]
                    imports.setdefault(top, []).append((path, node.lineno))
        return imports

    def _exists_on_pypi(self, name: str) -> bool:
        if name in self._pypi_cache:
            return self._pypi_cache[name]
        try:
            req = urllib.request.Request(PYPI_URL.format(name=name), method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                ok = resp.status == 200
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
            ok = False
        self._pypi_cache[name] = ok
        return ok
