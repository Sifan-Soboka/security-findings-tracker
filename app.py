"""Streamlit dashboard for NVD CVE findings and remediation tracking."""
import pandas as pd
import streamlit as st

from database import get_findings, initialize_database, update_finding, upsert_findings
from report_generator import export_csv, export_json
from risk_engine import DEFAULT_DATA_PATH, parse_dataset

st.set_page_config(page_title="Security Findings & Evidence Tracker", page_icon="🛡️", layout="wide")
st.title("🛡️ Security Findings & Evidence Tracker")
st.caption("Import NVD CVEs, prioritize findings, and track remediation evidence.")

initialize_database()

with st.sidebar:
    st.header("NVD Dataset")
    st.write("Expected file:")
    st.code("data/nvdcve-2.0-recent.json")
    if st.button("Import / Refresh NVD Data", type="primary", use_container_width=True):
        try:
            with st.spinner("Parsing all CVE records in the JSON file..."):
                parsed = parse_dataset()
                upsert_findings(parsed)
            st.success(f"Imported/refreshed {len(parsed):,} unique CVE records.")
            st.rerun()
        except Exception as exc:
            st.error(f"Import failed: {exc}")
    st.caption("This app processes the supplied dataset. It does not scan devices or networks.")

findings = get_findings()
if not findings:
    st.info("No findings are in the database yet. Use **Import / Refresh NVD Data** in the sidebar.")
    st.stop()

df = pd.DataFrame(findings)
total = len(df)
critical = int((df["severity"] == "CRITICAL").sum())
high = int((df["severity"] == "HIGH").sum())
open_count = int((df["status"] == "Open").sum())
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Findings", f"{total:,}")
m2.metric("Critical", f"{critical:,}")
m3.metric("High", f"{high:,}")
m4.metric("Open", f"{open_count:,}")

st.divider()
st.subheader("Vulnerability Findings")
c1, c2, c3 = st.columns([2, 1, 1])
with c1:
    query = st.text_input("Search CVE ID or description", placeholder="CVE-2026-...")
with c2:
    severity_values = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
    selected_severity = st.multiselect("Severity", severity_values, default=severity_values)
with c3:
    status_values = ["Open", "In Progress", "Mitigated", "Accepted Risk"]
    selected_status = st.multiselect("Status", status_values, default=status_values)

filtered = df[df["severity"].isin(selected_severity) & df["status"].isin(selected_status)].copy()
if query.strip():
    needle = query.strip()
    filtered = filtered[
        filtered["cve_id"].str.contains(needle, case=False, na=False)
        | filtered["description"].str.contains(needle, case=False, na=False)
    ]
st.caption(f"Showing {len(filtered):,} of {total:,} findings.")
st.dataframe(
    filtered[["cve_id", "severity", "cvss_score", "risk_score", "status", "published", "nvd_url"]],
    use_container_width=True,
    hide_index=True,
    column_config={
        "cvss_score": st.column_config.NumberColumn("CVSS", format="%.1f"),
        "risk_score": st.column_config.NumberColumn("Priority Score", format="%.1f"),
        "nvd_url": st.column_config.LinkColumn("NVD Details"),
    },
)

st.subheader("Severity Distribution")
chart_data = df["severity"].value_counts().reindex(severity_values, fill_value=0)
st.bar_chart(chart_data)

st.divider()
st.subheader("Remediation & Evidence Notes")
options = sorted(df["cve_id"].tolist())
selected_cve = st.selectbox("Select a CVE", options)
row = df.loc[df["cve_id"] == selected_cve].iloc[0]
st.write(row["description"])
st.markdown(f"[Open CVE on NVD]({row['nvd_url']})")
with st.form("update_finding"):
    statuses = ["Open", "In Progress", "Mitigated", "Accepted Risk"]
    current = row["status"] if row["status"] in statuses else "Open"
    status = st.selectbox("Remediation status", statuses, index=statuses.index(current))
    notes = st.text_area(
        "Analyst notes / evidence",
        value=row.get("analyst_notes", "") or "",
        placeholder="Record affected asset, investigation, fix, validation, or evidence reference.",
    )
    if st.form_submit_button("Save remediation update"):
        update_finding(selected_cve, status, notes)
        st.success("Finding updated.")
        st.rerun()

st.divider()
st.subheader("Export")
col_a, col_b = st.columns(2)
with col_a:
    csv_path = export_csv()
    st.download_button("Download CSV report", data=csv_path.read_bytes(),
                       file_name="security_findings.csv", mime="text/csv")
with col_b:
    json_path = export_json()
    st.download_button("Download JSON report", data=json_path.read_bytes(),
                       file_name="security_findings.json", mime="application/json")

st.caption("Priority Score = CVSS base score × 10 when available. It is a triage aid, not environment-specific risk.")
