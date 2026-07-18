import sqlite3
import threading
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "scans.db"
_lock = threading.Lock()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                findings_count INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                error TEXT,
                file_path TEXT,
                pdf_path TEXT,
                svc_path TEXT,
                progress INTEGER DEFAULT 0,
                current_task TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                finished_at TEXT
            )
        """)

        existing_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        if 'progress' not in existing_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN progress INTEGER DEFAULT 0")
        if 'current_task' not in existing_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN current_task TEXT DEFAULT ''")
        if 'pdf_path' not in existing_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN pdf_path TEXT")
        if 'svc_path' not in existing_columns:
            conn.execute("ALTER TABLE scans ADD COLUMN svc_path TEXT")
        conn.commit()


def create_scan(account_name: str) -> int:
    with _lock, sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO scans (account_name, status, progress, current_task) VALUES (?, 'running', 3, 'Queued')",
            (account_name,),
        )
        conn.commit()
        return cur.lastrowid


def mark_success(scan_id: int, file_path: str, findings_count: int, critical: int, high: int, pdf_path: Optional[str] = None, svc_path: Optional[str] = None):
    with _lock, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """UPDATE scans SET status='success', file_path=?, pdf_path=?, svc_path=?, findings_count=?,
               critical_count=?, high_count=?, progress=100, current_task='Completed',
               finished_at=datetime('now') WHERE id=?""",
            (file_path, pdf_path, svc_path, findings_count, critical, high, scan_id),
        )
        conn.commit()


def mark_failed(scan_id: int, error: str):
    with _lock, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """UPDATE scans SET status='failed', error=?, progress=100,
               current_task='Scan failed', finished_at=datetime('now') WHERE id=?""",
            (error[:500], scan_id),
        )
        conn.commit()


def update_progress(scan_id: int, progress: int, current_task: Optional[str] = None):
    with _lock, sqlite3.connect(DB_PATH) as conn:
        if current_task is None:
            conn.execute(
                "UPDATE scans SET progress=? WHERE id=?",
                (progress, scan_id),
            )
        else:
            conn.execute(
                "UPDATE scans SET progress=?, current_task=? WHERE id=?",
                (progress, current_task[:200], scan_id),
            )
        conn.commit()


def list_scans():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id: int):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None
