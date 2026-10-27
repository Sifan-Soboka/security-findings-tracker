"""Parse NVD JSON 2.0 vulnerability records and calculate transparent priority scores."""
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_PATH = BASE_DIR / "data" / "nvdcve-2.0-recent.json"


def load_nvd_json(file_path=DEFAULT_DATA_PATH):
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(
            f"NVD dataset not found: {path}\n"
            "Place nvdcve-2.0-recent.json in the project's data folder."
        )
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    records = payload.get("vulnerabilities")
    if not isinstance(records, list):
        raise ValueError("The file is not an expected NVD JSON 2.0 feed.")
    return records


def severity_from_score(score):
    score = float(score)
    if score == 0:
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if score < 9:
        return "HIGH"
    return "CRITICAL"


def extract_cvss(cve):
    """Return (score, severity, version); prefer NVD's primary metrics."""
    metrics = cve.get("metrics") or {}
    for metric_key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(metric_key) or []
        entries = sorted(
            entries,
            key=lambda item: (
                item.get("type") != "Primary",
                item.get("source") != "nvd@nist.gov",
            ),
        )
        for entry in entries:
            cvss = entry.get("cvssData") or {}
            score = cvss.get("baseScore")
            if score is None:
                continue
            severity = (
                cvss.get("baseSeverity")
                or entry.get("baseSeverity")
                or severity_from_score(score)
            )
            return float(score), str(severity).upper(), version
    return None, "UNKNOWN", None


def calculate_risk_score(cvss_score, severity):
    """Normalized 0-100 score; not an environment-specific risk assessment."""
    if cvss_score is not None:
        return round(max(0.0, min(100.0, float(cvss_score) * 10)), 1)
    fallback = {
        "CRITICAL": 95, "HIGH": 80, "MEDIUM": 55,
        "LOW": 25, "NONE": 0, "UNKNOWN": 30,
    }
    return float(fallback.get(str(severity).upper(), 30))


def parse_vulnerability(item):
    cve = item.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") or []
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        "",
    )
    cvss_score, severity, cvss_version = extract_cvss(cve)

    weaknesses = []
    for weakness in cve.get("weaknesses") or []:
        for entry in weakness.get("description") or []:
            if entry.get("lang") == "en" and entry.get("value"):
                if entry["value"] not in weaknesses:
                    weaknesses.append(entry["value"])

    return {
        "cve_id": cve_id,
        "description": description or "No English description available.",
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "risk_score": calculate_risk_score(cvss_score, severity),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "weaknesses": ", ".join(weaknesses),
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def parse_dataset(file_path=DEFAULT_DATA_PATH):
    findings = []
    seen = set()
    for item in load_nvd_json(file_path):
        finding = parse_vulnerability(item)
        if finding and finding["cve_id"] not in seen:
            findings.append(finding)
            seen.add(finding["cve_id"])
    return findings
