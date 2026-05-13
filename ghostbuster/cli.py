"""GhostBuster CLI.

Usage:
    python -m ghostbuster scan [PATH] [--threshold 40] [--report-dir reports] [--no-pypi] [--fail-on-threshold]
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from .engine import GhostBusterEngine, EngineConfig
from .reporting import write_json_report, write_markdown_report, write_pr_summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ghostbuster", description="AI Hallucination & Security Validator")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a directory")
    s.add_argument("path", nargs="?", default=".", help="Path to scan (default: cwd)")
    s.add_argument("--threshold", type=float, default=40.0, help="Risk score threshold for PASS/FAIL")
    s.add_argument("--report-dir", default="reports", help="Directory to write reports into")
    s.add_argument("--no-pypi", action="store_true", help="Skip PyPI lookups for hallucinated-dep checks")
    s.add_argument("--no-tools", action="store_true", help="Skip Bandit/pip-audit/Trivy")
    s.add_argument("--fail-on-threshold", action="store_true",
                   help="Exit non-zero when risk score >= threshold")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd != "scan":
        return 2

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2

    cfg = EngineConfig(
        target=target,
        threshold=args.threshold,
        check_pypi=not args.no_pypi,
        enable_security_tools=not args.no_tools,
    )
    result = GhostBusterEngine(cfg).run()

    report_dir = Path(args.report_dir)
    json_path = write_json_report(result.findings, result.score, result.verdict, report_dir / "ghostbuster-report.json")
    md_path = write_markdown_report(result.findings, result.score, result.verdict, args.threshold, report_dir / "ghostbuster-report.md")
    pr_path = write_pr_summary(result.findings, result.score, result.verdict, args.threshold, report_dir / "pr-summary.md")

    print("=" * 60)
    print(f"GhostBuster CI/CD — verdict: {result.verdict}")
    print(f"Risk score : {result.score['score']} / 100  (threshold {args.threshold})")
    print(f"Findings   : {result.score['total_findings']}")
    print(f"By severity: {result.score['severity_counts']}")
    print(f"Reports    : {json_path}, {md_path}, {pr_path}")
    print("=" * 60)

    if args.fail_on_threshold and result.verdict == "FAIL":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
