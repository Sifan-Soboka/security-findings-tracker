"""SQLite persistence for the Security Findings & Evidence Tracker."""
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
# A fresh database name avoids collisions with the older, incompatible schema.
DEFAULT_DB_PATH = BASE_DIR / "data" / "security_findings_v2.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
    cvss_score REAL,
    cvss_version TEXT,
    risk_score REAL NOT NULL DEFAULT 30,
    published TEXT,
    last_modified TEXT,
    weaknesses TEXT,
    nvd_url TEXT,
    status TEXT NOT NULL DEFAULT 'Open',
    analyst_notes TEXT NOT NULL DEFAULT '',
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""


def get_connection(db_path=DEFAULT_DB_PATH):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database(db_path=DEFAULT_DB_PATH):
    with get_connection(db_path) as conn:
        conn.execute(SCHEMA)


def upsert_findings(findings, db_path=DEFAULT_DB_PATH):
    """Refresh CVE details while retaining each analyst's status and notes."""
    initialize_database(db_path)
    sql = """
    INSERT INTO findings (
        cve_id, description, severity, cvss_score, cvss_version,
        risk_score, published, last_modified, weaknesses, nvd_url
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET
        description=excluded.description,
        severity=excluded.severity,
        cvss_score=excluded.cvss_score,
        cvss_version=excluded.cvss_version,
        risk_score=excluded.risk_score,
        published=excluded.published,
        last_modified=excluded.last_modified,
        weaknesses=excluded.weaknesses,
        nvd_url=excluded.nvd_url,
        imported_at=CURRENT_TIMESTAMP
    """
    rows = [
        (
            f["cve_id"], f["description"], f["severity"], f["cvss_score"],
            f["cvss_version"], f["risk_score"], f["published"],
            f["last_modified"], f["weaknesses"], f["nvd_url"],
        )
        for f in findings
    ]
    with get_connection(db_path) as conn:
        conn.executemany(sql, rows)
    return len(rows)


def get_findings(db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY risk_score DESC, cve_id ASC"
        ).fetchall()
    return [dict(row) for row in rows]


def update_finding(cve_id, status, analyst_notes, db_path=DEFAULT_DB_PATH):
    allowed = {"Open", "In Progress", "Mitigated", "Accepted Risk"}
    if status not in allowed:
        raise ValueError(f"Invalid status: {status}")
    initialize_database(db_path)
    with get_connection(db_path) as conn:
        cur = conn.execute(
            "UPDATE findings SET status=?, analyst_notes=? WHERE cve_id=?",
            (status, analyst_notes, cve_id),
        )
        if cur.rowcount == 0:
            raise ValueError(f"Finding not found: {cve_id}")


def get_finding_count(db_path=DEFAULT_DB_PATH):
    initialize_database(db_path)
    with get_connection(db_path) as conn:
        return conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
