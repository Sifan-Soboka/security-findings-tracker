# Security Findings & Evidence Tracker

A defensive vulnerability-management learning project. It imports CVE records from the supplied NVD JSON 2.0 recent feed, calculates transparent prioritization scores, stores findings in SQLite, and tracks remediation status and analyst evidence notes.

## Features
- Parse multiple CVEs from the NVD JSON 2.0 feed.
- Extract descriptions, CVSS scores, severity, dates, weaknesses, and NVD links.
- Normalize CVSS into a 0–100 priority score when available.
- Persist findings in SQLite while preserving remediation status and analyst notes on refresh.
- Search/filter findings, review severity distribution, and export CSV/JSON reports.

## Setup (Windows PowerShell)
Run these commands from the folder containing `app.py`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Use the **Import / Refresh NVD Data** button in the dashboard sidebar.

## Dataset
The project includes `data/nvdcve-2.0-recent.json`, the dataset supplied for this project. The NVD recent feed is a limited recent-data feed, not the complete historical NVD database.

## Database
The application uses `data/security_findings_v2.db`. This separate filename intentionally avoids conflict with an older database schema from previous attempts. The old `data/security_findings.db` is not deleted or modified.

## Tests
```powershell
python -m unittest discover -s tests -v
```

## Scoring and limitations
When a CVSS score exists, `Priority Score = CVSS base score × 10`. If CVSS is absent, the app uses a severity-based fallback. This score is a triage aid, not proof that a vulnerability is exploitable or that it affects a particular asset. The app does not scan devices or networks and does not determine actual organizational risk without asset context.

## Ethical use
Use this project for learning and defensive vulnerability management. Validate findings against vendor guidance and the assets in scope.
