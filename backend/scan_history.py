"""
Aegis — Scan History Persistence
SQLite storage for threat scan results. Survives restarts, enables posture timeline.
"""
import os
import sqlite3
import json
from datetime import datetime

# Store in the same directory as the backend
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aegis_scan_history.db')


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            score INTEGER NOT NULL,
            total_findings INTEGER NOT NULL DEFAULT 0,
            critical INTEGER NOT NULL DEFAULT 0,
            high INTEGER NOT NULL DEFAULT 0,
            medium INTEGER NOT NULL DEFAULT 0,
            low INTEGER NOT NULL DEFAULT 0,
            info INTEGER NOT NULL DEFAULT 0,
            duration_ms INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            rule_id TEXT,
            severity TEXT,
            category TEXT,
            title TEXT,
            detail TEXT,
            recommendation TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
    """)
    conn.commit()
    conn.close()


def save_scan(score, findings, duration_ms=0):
    """Persist a completed scan and its findings. Returns scan_id."""
    conn = _get_conn()
    try:
        sev = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            s = f.get('severity', 'info').lower()
            if s in sev:
                sev[s] += 1

        cur = conn.execute(
            """INSERT INTO scans (timestamp, score, total_findings, critical, high, medium, low, info, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(), score, len(findings),
             sev['critical'], sev['high'], sev['medium'], sev['low'], sev['info'],
             duration_ms)
        )
        scan_id = cur.lastrowid

        for f in findings:
            conn.execute(
                """INSERT INTO findings (scan_id, rule_id, severity, category, title, detail, recommendation)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, f.get('id', ''), f.get('severity', ''),
                 f.get('category', ''), f.get('title', ''),
                 f.get('detail', ''), f.get('recommendation', ''))
            )

        conn.commit()
        return scan_id
    finally:
        conn.close()


def get_history(limit=50):
    """Return recent scan summaries (newest first)."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_detail(scan_id):
    """Return a single scan with its findings."""
    conn = _get_conn()
    try:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            return None
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)
        ).fetchall()
        result = dict(scan)
        result['findings'] = [dict(f) for f in findings]
        return result
    finally:
        conn.close()


# Init on import
init_db()
