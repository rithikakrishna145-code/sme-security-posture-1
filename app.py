"""
app.py — Streamlit dashboard. Run with: streamlit run dashboard/app.py
"""

import json
import os
import streamlit as st
import pandas as pd

st.set_page_config(page_title="SME Security Posture Dashboard", page_icon="🛡️", layout="wide")

RATING_COLORS = {"Strong": "#1E7A46", "Moderate": "#D98C3D", "Weak": "#C9622A", "Critical": "#B3261E"}


@st.cache_data
def load_reports():
    path = os.path.join(os.path.dirname(__file__), "..", "data", "processed", "posture_reports.json")
    with open(path) as f:
        return json.load(f)


def main():
    st.title("🛡️ SME Security Posture Dashboard")
    st.caption("PSAIAC_277 — Explainable, CIS-grounded scoring with ML-driven anomaly detection")

    try:
        reports = load_reports()
    except FileNotFoundError:
        st.error("No posture reports found. Run `python src/data_generator.py` then `python src/run_pipeline.py` first.")
        return

    org_names = [r["org_name"] for r in reports]
    selected_org = st.sidebar.selectbox("Select Organization", org_names)
    report = next(r for r in reports if r["org_name"] == selected_org)

    st.sidebar.markdown("---")
    st.sidebar.markdown("**All Organizations**")
    for r in reports:
        color = RATING_COLORS.get(r["rating"], "#666")
        st.sidebar.markdown(f"<span style='color:{color}'>●</span> {r['org_name']}: **{r['total_score']}/100** ({r['rating']})",
                             unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        st.metric("Posture Score", f"{report['total_score']:.0f} / 100")
    with col2:
        color = RATING_COLORS.get(report["rating"], "#666")
        st.markdown(f"<h3 style='color:{color}'>{report['rating']}</h3>", unsafe_allow_html=True)
    with col3:
        st.progress(min(report["total_score"] / 100, 1.0))

    st.markdown("---")
    st.subheader("Category Breakdown")
    cat_data = report["category_breakdown"]
    cat_df = pd.DataFrame([{"Category": cat, "Score": vals["awarded"], "Max": vals["possible"]}
                            for cat, vals in cat_data.items()])
    st.bar_chart(cat_df.set_index("Category")["Score"])

    cols = st.columns(len(cat_data))
    for col, (cat, vals) in zip(cols, cat_data.items()):
        with col:
            st.metric(cat, f"{vals['awarded']:.1f} / {vals['possible']:.0f}")

    st.markdown("---")
    st.subheader("Detailed Findings")
    st.caption("Every point on this score traces back to one of these checks — nothing here is a black box.")
    findings_df = pd.DataFrame(report["findings"])
    findings_df["Status"] = findings_df["passed"].apply(lambda x: "✅ Pass" if x else "❌ Fail")
    display_df = findings_df[["category", "check_name", "Status", "points_awarded", "points_possible", "detail"]]
    display_df.columns = ["Category", "Check", "Status", "Points Awarded", "Points Possible", "Detail"]
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.subheader("🤖 Anomaly Detection (Isolation Forest)")
    ml_val = report.get("ml_validation")
    if ml_val:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Precision", ml_val["precision"])
        c2.metric("Recall", ml_val["recall"])
        c3.metric("True Positives", ml_val["true_positives"])
        c4.metric("False Positives", ml_val["false_positives"])
        st.caption("Validated against injected synthetic anomalies. High recall means the model "
                   "catches real anomalies reliably.")


if __name__ == "__main__":
    main()
