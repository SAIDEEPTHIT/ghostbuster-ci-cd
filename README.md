# 👻 GhostBuster CI/CD — AI Hallucination & Security Validator

> An AI-aware DevSecOps validation pipeline for secure AI-assisted software development.

GhostBuster is a CI/CD-native security gate that detects **AI-generated risky code**, **hallucinated dependencies**, **hardcoded secrets**, **dangerous system calls**, and **known CVEs** — *before* code is deployed. It pairs a modular Python scanning engine with **Bandit**, **pip-audit**, and **Trivy**, runs automatically on every push/PR via **GitHub Actions**, scores the risk, comments on the PR, and ships a polished **Streamlit dashboard** for analysts.

---

## ✨ Why GhostBuster?

LLM-assisted coding ships three new classes of bug into production every day:

| Risk | What it looks like | GhostBuster catches it via |
|------|--------------------|----------------------------|
| **Hallucinated dependencies** | `import openaiwrapper` (does not exist) | AST + PyPI existence check + typosquat list |
| **Placeholder / unfinished code** | `# your code here`, ` ```python ` fences | Curated regex pattern set (CRITICAL→LOW) |
| **AI-leaked credentials** | `OPENAI_API_KEY = "sk-…"` | High-precision secret regexes + Shannon entropy |
| **Risky system calls** | `eval`, `pickle.loads`, `shell=True` | Python AST inspection |
| **Known CVEs / misconfigs** | Vulnerable transitive deps | Bandit + pip-audit + Trivy |

---

## 🏛 Architecture

```text
                          ┌─────────────────────────┐
   git push / PR ───────► │  GitHub Actions runner  │
                          └──────────┬──────────────┘
                                     │
                          ┌──────────▼──────────┐
                          │  GhostBuster Engine │
                          └──────────┬──────────┘
        ┌──────────┬──────────┬──────┼──────┬──────────────┐
        ▼          ▼          ▼      ▼      ▼              ▼
   AIPattern   Hallucinated Dangerous Secrets  Bandit   pip-audit / Trivy
                Deps         Code
        └──────────┴──────────┴──────┬──────┴──────────────┘
                                     ▼
                       ┌──────────────────────────┐
                       │  Risk Scoring Engine     │
                       │  (weighted, log-squashed)│
                       └──────────┬───────────────┘
                                  ▼
                ┌──────────────┬──────────────┬─────────────────┐
                ▼              ▼              ▼                 ▼
          JSON report   Markdown report  PR comment       Streamlit dashboard
                                  │
                                  ▼
                       PASS / FAIL deploy gate
```

### Folder layout

```
ghostbuster-ci-cd/
├── ghostbuster/                  # Engine + scanners (importable package)
│   ├── engine.py                 # Orchestrator
│   ├── risk.py                   # Weighted scoring
│   ├── cli.py / __main__.py      # `python -m ghostbuster scan ...`
│   ├── severity.py               # Severity enum + Finding dataclass
│   ├── scanners/
│   │   ├── ai_patterns.py        # Placeholders, AI markers, leaked fences
│   │   ├── hallucinated_deps.py  # AST + PyPI existence check
│   │   ├── dangerous_code.py     # AST: eval/exec/pickle/shell=True/...
│   │   ├── secrets.py            # Regex + Shannon entropy
│   │   └── security_tools.py     # Bandit + pip-audit + Trivy wrappers
│   └── reporting/report.py       # JSON / Markdown / PR-summary
├── dashboard/app.py              # Streamlit UI
├── demo_vulnerable/              # Intentionally bad code (demo target)
├── tests/test_scanners.py        # Pytest coverage
├── .github/workflows/ghostbuster.yml
├── requirements.txt
└── pyproject.toml
```

---

## 🚀 Quick start

### 1. Local install

```bash
git clone https://github.com/<you>/ghostbuster-ci-cd.git
cd ghostbuster-ci-cd
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### 2. Scan something

```bash
# Scan the bundled vulnerable demo (should FAIL):
python -m ghostbuster scan demo_vulnerable --threshold 10 --fail-on-threshold

# Scan your own project:
python -m ghostbuster scan /path/to/repo --threshold 40
```

Reports land in `reports/`:
- `ghostbuster-report.json` — machine-readable
- `ghostbuster-report.md` — full human-readable
- `pr-summary.md` — short PR comment

### 3. Launch the dashboard

```bash
streamlit run dashboard/app.py
```

Then either click **▶ Run scan** or upload a previously generated `ghostbuster-report.json`.

### 4. Run tests

```bash
pip install pytest
pytest -q
```

---

## 🤖 GitHub Actions integration

The workflow at `.github/workflows/ghostbuster.yml` runs on **push**, **pull_request**, and **workflow_dispatch** (manual). It:

1. Installs Python deps, **Bandit**, **pip-audit**, and **Trivy**.
2. Runs `python -m ghostbuster scan . --threshold 40 --fail-on-threshold`.
3. Uploads `reports/` as a build artifact.
4. Posts the PR-summary as a comment on the pull request.
5. Writes the summary to the GitHub job summary panel.
6. **Fails the build** if the risk score exceeds the configured threshold — gating deploys.

To change the threshold per-run, use **Actions → GhostBuster CI/CD → Run workflow** and pass a custom value.

---

## 📊 Risk scoring

Each finding is weighted by severity (`LOW=1`, `MEDIUM=4`, `HIGH=9`, `CRITICAL=20`) and multiplied by a category-specific factor (secrets and command-injection get an extra boost). The raw weighted sum is squashed via `20·ln(1+raw)` and clamped to **0–100** so a single critical finding won't peg the meter, but a cluster of them will. The pipeline fails when `score ≥ threshold`.

---

## 🧪 Demo / talking points

The `demo_vulnerable/` directory contains intentionally bad code: hallucinated imports (`openaiwrapper`, `ai_security_lib`, `reqeusts`), hardcoded `sk-…`/`AKIA…`/`ghp_…` keys, `eval`, `pickle.loads`, `subprocess(..., shell=True)`, leaked AI-assistant disclaimers, and weak crypto. Running:

```bash
python -m ghostbuster scan demo_vulnerable --threshold 10 --fail-on-threshold
```

…produces a non-zero exit code and a complete report — perfect for live demos.

---

## 🛠 Tools used

- **Python 3.10+** • AST, regex, urllib (PyPI lookups)
- **Streamlit** + **pandas** for the analyst dashboard
- **Bandit** — Python security linter
- **pip-audit** — Python dependency CVE scanner
- **Trivy** — filesystem CVE & misconfiguration scanner
- **GitHub Actions** — CI/CD orchestration & PR commenting

---

## 🔭 Future scope

- Semgrep + CodeQL integration
- SBOM generation (CycloneDX) and signing (cosign / SLSA)
- Slack / Teams notifications on FAIL
- Historical trend tracking (SQLite + dashboard timeline)
- Auto-fix PRs for safe transformations (`yaml.load → yaml.safe_load`, etc.)
- LLM-based explanation layer (severity rationales in plain English)
- VS Code extension for local pre-commit scans

---

## 📄 License

MIT — see [LICENSE](LICENSE).
