import json
import os
import sqlite3
from typing import Any, Dict, List


_conn: sqlite3.Connection | None = None


def _get_db_path() -> str:
    path = os.environ.get("SECURITY_ANALYZER_DB_PATH", ":memory:")
    return str(path)


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        db_path = _get_db_path()
        _conn = sqlite3.connect(db_path)
        _conn.row_factory = sqlite3.Row
    return _conn


def init_db() -> None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            type TEXT,
            risk_score INTEGER,
            confidence REAL,
            verdict TEXT,
            signals TEXT,
            breakdown TEXT,
            explain TEXT
        )
        """
    )
    conn.commit()


def save_analysis(result: Dict[str, Any], explain: Dict[str, Any]) -> int:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO analyses (target, type, risk_score, confidence, verdict, signals, breakdown, explain) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            result.get("target"),
            result.get("type"),
            int(result.get("risk_score", 0)),
            float(result.get("confidence", 0.0)),
            result.get("verdict"),
            json.dumps(result.get("signals", [])),
            json.dumps(result.get("breakdown", {})),
            json.dumps(explain),
        ),
    )
    conn.commit()
    return cur.lastrowid


def list_history(limit: int = 10) -> List[Dict[str, Any]]:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM analyses ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    return [{"id": r[0]} for r in rows]


def _get_by_id(analysis_id: int) -> sqlite3.Row | None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    return cur.fetchone()


def get_explain(analysis_id: int) -> Dict[str, Any] | None:
    row = _get_by_id(analysis_id)
    if not row:
        return None
    explain = json.loads(row["explain"]) if isinstance(row["explain"], str) else row["explain"]
    return {"id": row["id"], "explain": explain, "scoring": explain.get("scoring")}  # expose scoring for test


def clear_history() -> None:
    conn = _get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM analyses")
    conn.commit()
