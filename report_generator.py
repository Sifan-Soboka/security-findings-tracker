"""Export database findings as CSV and JSON."""
import csv
import json
from pathlib import Path
from database import get_findings

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_REPORT_DIR = BASE_DIR / "reports"


def export_csv(output_path=None):
    output = Path(output_path) if output_path else DEFAULT_REPORT_DIR / "security_findings.csv"
    output.parent.mkdir(parents=True, exist_ok=True)
    findings = get_findings()
    fields = [
        "cve_id", "description", "severity", "cvss_score", "cvss_version",
        "risk_score", "published", "last_modified", "weaknesses", "nvd_url",
        "status", "analyst_notes", "imported_at",
    ]
    with output.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)
    return output


def export_json(output_path=None):
    output = Path(output_path) if output_path else DEFAULT_REPORT_DIR / "security_findings.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    findings = get_findings()
    report = {
        "project": "Security Findings & Evidence Tracker",
        "total_findings": len(findings),
        "severity_summary": {},
        "status_summary": {},
        "findings": findings,
    }
    for finding in findings:
        sev, status = finding["severity"], finding["status"]
        report["severity_summary"][sev] = report["severity_summary"].get(sev, 0) + 1
        report["status_summary"][status] = report["status_summary"].get(status, 0) + 1
    with output.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    return output
