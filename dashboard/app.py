"""GhostBuster Streamlit dashboard.

Run: streamlit run dashboard/app.py
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ghostbuster.engine import GhostBusterEngine, EngineConfig  # noqa: E402

st.set_page_config(
    page_title="GhostBuster CI/CD",
    page_icon="👻",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---- styling -------------------------------------------------------------
st.markdown("""
<style>
.main { background: #0b1020; }
section[data-testid="stSidebar"] { background: #0e1530; }
h1, h2, h3, h4 { color: #e6ecff !important; letter-spacing: -0.02em; }
.metric-card {
    background: linear-gradient(135deg, rgba(99,102,241,0.12), rgba(14,165,233,0.06));
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 14px; padding: 18px 20px; color: #e6ecff;
}
.verdict-pass { color: #34d399; font-weight: 700; font-size: 28px; }
.verdict-fail { color: #f87171; font-weight: 700; font-size: 28px; }
.score { font-size: 44px; font-weight: 800; color: #e6ecff; }
.pill {
    display:inline-block; padding:3px 10px; border-radius:999px;
    font-size:12px; font-weight:600; margin-right:6px;
}
.pill-CRITICAL { background:#7f1d1d; color:#fee2e2; }
.pill-HIGH { background:#9a3412; color:#ffedd5; }
.pill-MEDIUM { background:#78350f; color:#fef3c7; }
.pill-LOW { background:#064e3b; color:#d1fae5; }
.code-snip { background:#0f172a; padding:8px 10px; border-radius:8px;
    font-family: ui-monospace, monospace; font-size:12px; color:#cbd5e1; }
</style>
""", unsafe_allow_html=True)

# ---- sidebar -------------------------------------------------------------
st.sidebar.title("👻 GhostBuster")
st.sidebar.caption("AI Hallucination & Security Validator")

mode = st.sidebar.radio("Source", ["Run live scan", "Load report JSON"], index=0)
threshold = st.sidebar.slider("Risk threshold (PASS/FAIL)", 0, 100, 40)

if mode == "Run live scan":
    target = st.sidebar.text_input("Target path", str(ROOT / "demo_vulnerable"))
    use_pypi = st.sidebar.checkbox("Check PyPI for hallucinated deps", value=True)
    use_tools = st.sidebar.checkbox("Run Bandit / pip-audit / Trivy", value=True)
    if st.sidebar.button("▶ Run scan", use_container_width=True, type="primary"):
        with st.spinner("Scanning…"):
            cfg = EngineConfig(
                target=Path(target).resolve(), threshold=threshold,
                check_pypi=use_pypi, enable_security_tools=use_tools,
            )
            res = GhostBusterEngine(cfg).run()
            st.session_state["report"] = {
                "verdict": res.verdict,
                "score": res.score,
                "findings": [f.to_dict() for f in res.findings],
            }
else:
    up = st.sidebar.file_uploader("Upload ghostbuster-report.json", type=["json"])
    if up is not None:
        st.session_state["report"] = json.load(up)

report = st.session_state.get("report")

# ---- header --------------------------------------------------------------
st.title("GhostBuster CI/CD")
st.caption("AI-aware DevSecOps validation — block hallucinated deps, secret leaks, and risky AI-generated code before deploy.")

if not report:
    st.info("Run a scan or upload a report from the sidebar to begin.")
    st.stop()

score = report["score"]
verdict = report["verdict"]
findings = report["findings"]

# ---- top metrics ---------------------------------------------------------
c1, c2, c3, c4, c5 = st.columns([1.4, 1, 1, 1, 1])
with c1:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.markdown("**Pipeline verdict**")
    cls = "verdict-pass" if verdict == "PASS" else "verdict-fail"
    icon = "✅" if verdict == "PASS" else "❌"
    st.markdown(f'<div class="{cls}">{icon} {verdict}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="score">{score["score"]}</div>', unsafe_allow_html=True)
    st.caption(f"Risk score / 100  •  threshold {threshold}")
    st.markdown("</div>", unsafe_allow_html=True)

sc = score["severity_counts"]
for col, sev, color in zip(
    [c2, c3, c4, c5],
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    ["#f87171", "#fb923c", "#fbbf24", "#34d399"],
):
    with col:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.markdown(f"**{sev}**")
        st.markdown(f'<div class="score" style="color:{color}">{sc.get(sev, 0)}</div>', unsafe_allow_html=True)
        st.caption("findings")
        st.markdown("</div>", unsafe_allow_html=True)

st.markdown("---")

# ---- charts --------------------------------------------------------------
left, right = st.columns(2)
with left:
    st.subheader("Severity distribution")
    sev_df = pd.DataFrame({
        "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "count": [sc.get(s, 0) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]],
    })
    st.bar_chart(sev_df.set_index("severity"), color="#6366f1")

with right:
    st.subheader("Findings by scanner")
    by_sc = score.get("by_scanner", {})
    if by_sc:
        st.bar_chart(pd.DataFrame({"count": by_sc}), color="#0ea5e9")
    else:
        st.write("No data.")

st.subheader("Categories")
cat = score.get("category_counts", {})
if cat:
    st.bar_chart(pd.DataFrame({"count": cat}), color="#a78bfa")

# ---- findings table ------------------------------------------------------
st.markdown("---")
st.subheader(f"Findings ({len(findings)})")

if findings:
    df = pd.DataFrame(findings)
    sev_filter = st.multiselect("Filter by severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                default=["CRITICAL", "HIGH", "MEDIUM"])
    cats = sorted(df["category"].dropna().unique().tolist())
    cat_filter = st.multiselect("Filter by category", cats, default=cats)
    fdf = df[df["severity"].isin(sev_filter) & df["category"].isin(cat_filter)]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    fdf = fdf.assign(_o=fdf["severity"].map(order)).sort_values("_o").drop(columns="_o")
    st.dataframe(
        fdf[["severity", "scanner", "category", "title", "file", "line", "snippet"]],
        use_container_width=True, hide_index=True, height=420,
    )
else:
    st.success("No findings — clean run.")

# ---- downloads -----------------------------------------------------------
st.markdown("---")
st.subheader("Reports")
d1, d2 = st.columns(2)
with d1:
    st.download_button(
        "⬇ Download JSON report",
        data=json.dumps(report, indent=2),
        file_name="ghostbuster-report.json",
        mime="application/json",
        use_container_width=True,
    )
with d2:
    md_lines = [f"# GhostBuster Report — {verdict}", f"Score: {score['score']}/100", ""]
    for f in findings:
        md_lines.append(f"- **{f['severity']}** [{f['scanner']}] {f['title']} — `{f.get('file')}:{f.get('line')}`")
    st.download_button(
        "⬇ Download Markdown report",
        data="\n".join(md_lines),
        file_name="ghostbuster-report.md",
        mime="text/markdown",
        use_container_width=True,
    )
