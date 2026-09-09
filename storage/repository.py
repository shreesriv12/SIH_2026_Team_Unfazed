from __future__ import annotations
import json, os, sqlite3, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from config import settings

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "data" / "securemailscope.db"
SCHEMA = """CREATE TABLE IF NOT EXISTS analyses (id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, report_json TEXT NOT NULL, workspace_id TEXT);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE, session_key TEXT NOT NULL, protocol TEXT NOT NULL, transition TEXT NOT NULL, risk_score INTEGER NOT NULL, confidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE, session_key TEXT, rule_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, evidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, source TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, frame TEXT, timestamp TEXT, raw_value TEXT, derived_value TEXT, confidence TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS captures (sha256 TEXT PRIMARY KEY, storage_path TEXT NOT NULL, byte_size INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS capture_workspaces (sha256 TEXT NOT NULL REFERENCES captures(sha256), workspace_id TEXT NOT NULL, PRIMARY KEY (sha256, workspace_id));
CREATE TABLE IF NOT EXISTS custody_events (id TEXT PRIMARY KEY, sha256 TEXT NOT NULL REFERENCES captures(sha256), action TEXT NOT NULL, created_at TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL, detail TEXT NOT NULL, workspace_id TEXT, actor_id TEXT, ip_address TEXT);
CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, workspace_id TEXT NOT NULL REFERENCES workspaces(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS analysis_jobs (id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL, workspace_id TEXT NOT NULL, requested_by TEXT NOT NULL, status TEXT NOT NULL, error TEXT, analysis_id TEXT, attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS refresh_tokens (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, workspace_id TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS password_reset_tokens (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT NOT NULL);"""

def connection() -> tuple[Any, bool]:
    url = settings.database_url
    if url.startswith(("postgres://", "postgresql://")):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as error: raise RuntimeError("PostgreSQL requires psycopg; run python -m pip install -r requirements.txt") from error
        database = psycopg.connect(url, row_factory=dict_row, connect_timeout=5)
        return database, True
    path = Path(os.environ.get("SECUREMAILSCOPE_DATABASE_PATH", str(DEFAULT_PATH))); path.parent.mkdir(parents=True, exist_ok=True)
    database = sqlite3.connect(path); database.row_factory = sqlite3.Row; database.execute("PRAGMA foreign_keys = ON"); database.executescript(SCHEMA)
    existing_columns = {row["name"] for row in database.execute("PRAGMA table_info(audit_events)").fetchall()}
    for column in ("workspace_id", "actor_id", "ip_address"):
        if column not in existing_columns: database.execute(f"ALTER TABLE audit_events ADD COLUMN {column} TEXT")
    job_columns = {row["name"] for row in database.execute("PRAGMA table_info(analysis_jobs)").fetchall()}
    if "attempt" not in job_columns: database.execute("ALTER TABLE analysis_jobs ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0")
    if "max_attempts" not in job_columns: database.execute("ALTER TABLE analysis_jobs ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 3")
    database.commit()
    return database, False

def execute(database: Any, postgres: bool, sql: str, values: tuple[Any, ...]): return database.execute(sql.replace("?", "%s") if postgres else sql, values)

def store_capture(content: bytes, suffix: str, workspace_id: str, detail: str = "upload") -> tuple[str, Path]:
    import hashlib
    sha256 = hashlib.sha256(content).hexdigest(); directory = Path("data/captures"); directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{sha256}{suffix.lower()}"; created_at = datetime.now(timezone.utc).isoformat(); database, postgres = connection()
    try:
        existing = execute(database, postgres, "SELECT sha256 FROM captures WHERE sha256 = ?", (sha256,)).fetchone()
        if not existing:
            path.write_bytes(content)
            execute(database, postgres, "INSERT INTO captures VALUES (?, ?, ?, ?)", (sha256, str(path.resolve()), len(content), created_at))
        execute(database, postgres, "INSERT INTO capture_workspaces (sha256, workspace_id) SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM capture_workspaces WHERE sha256 = ? AND workspace_id = ?)", (sha256, workspace_id, sha256, workspace_id))
        execute(database, postgres, "INSERT INTO custody_events VALUES (?, ?, ?, ?, ?)", (str(uuid.uuid4()), sha256, "UPLOADED" if not existing else "DEDUPLICATED", created_at, detail))
        database.commit()
    finally: database.close()
    return sha256, path.resolve()

def record_custody(sha256: str, action: str, detail: str) -> None:
    database, postgres = connection()
    try:
        execute(database, postgres, "INSERT INTO custody_events VALUES (?, ?, ?, ?, ?)", (str(uuid.uuid4()), sha256, action, datetime.now(timezone.utc).isoformat(), detail)); database.commit()
    finally: database.close()

def audit(action: str, target: str, detail: str, workspace_id: str | None = None, actor_id: str | None = None, ip_address: str | None = None) -> None:
    safe_detail = " ".join(str(detail).replace("\x00", "").split())[:1000]
    database, postgres = connection()
    try:
        execute(database, postgres, "INSERT INTO audit_events (id, action, target, created_at, detail, workspace_id, actor_id, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (str(uuid.uuid4()), action, target, datetime.now(timezone.utc).isoformat(), safe_detail, workspace_id, actor_id, ip_address)); database.commit()
    finally: database.close()

def list_audit_events(workspace_id: str, action: str | None = None, actor_id: str | None = None, from_date: str | None = None, to_date: str | None = None, page: int = 1, page_size: int = 25) -> dict[str, Any]:
    clauses, values = ["workspace_id = ?"], [workspace_id]
    if action: clauses.append("action = ?"); values.append(action.upper())
    if actor_id: clauses.append("actor_id = ?"); values.append(actor_id)
    if from_date: clauses.append("created_at >= ?"); values.append(from_date)
    if to_date: clauses.append("created_at <= ?"); values.append(to_date)
    where = " AND ".join(clauses); database, postgres = connection()
    try:
        total = execute(database, postgres, f"SELECT COUNT(*) AS count FROM audit_events WHERE {where}", tuple(values)).fetchone()["count"]
        rows = execute(database, postgres, f"SELECT id, action, target, created_at, detail, actor_id, ip_address FROM audit_events WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?", tuple([*values, page_size, (page - 1) * page_size])).fetchall()
    finally: database.close()
    return {"items": [dict(row) for row in rows], "total": total, "page": page, "page_size": page_size}

def retention_candidates(days: int, workspace_id: str) -> list[dict[str, Any]]:
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(); database, postgres = connection()
    try: rows = execute(database, postgres, "SELECT c.sha256, c.storage_path, c.byte_size, c.created_at FROM captures c JOIN capture_workspaces w ON w.sha256 = c.sha256 WHERE c.created_at < ? AND w.workspace_id = ? ORDER BY c.created_at", (cutoff, workspace_id)).fetchall()
    finally: database.close()
    return [dict(row) for row in rows]

def retention_candidates_all(days: int) -> list[dict[str, Any]]:
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(); database, postgres = connection()
    try: rows = execute(database, postgres, "SELECT sha256, storage_path, byte_size, created_at FROM captures WHERE created_at < ? ORDER BY created_at", (cutoff,)).fetchall()
    finally: database.close()
    return [dict(row) for row in rows]

def capture_workspaces(sha256: str) -> list[str]:
    database, postgres = connection()
    try: rows = execute(database, postgres, "SELECT workspace_id FROM capture_workspaces WHERE sha256 = ?", (sha256,)).fetchall()
    finally: database.close()
    return [row["workspace_id"] for row in rows]

def purge_capture(sha256: str, workspace_id: str) -> bool:
    database, postgres = connection()
    try:
        row = execute(database, postgres, "SELECT c.storage_path FROM captures c JOIN capture_workspaces w ON w.sha256 = c.sha256 WHERE c.sha256 = ? AND w.workspace_id = ?", (sha256, workspace_id)).fetchone()
        if not row: return False
        path = Path(row["storage_path"]).resolve(); root = Path("data/captures").resolve()
        if root not in path.parents: raise RuntimeError("Refusing to delete a capture outside managed storage.")
        execute(database, postgres, "DELETE FROM capture_workspaces WHERE sha256 = ? AND workspace_id = ?", (sha256, workspace_id))
        remaining = execute(database, postgres, "SELECT 1 FROM capture_workspaces WHERE sha256 = ?", (sha256,)).fetchone()
        if not remaining:
            if path.exists(): path.unlink()
            execute(database, postgres, "DELETE FROM custody_events WHERE sha256 = ?", (sha256,)); execute(database, postgres, "DELETE FROM captures WHERE sha256 = ?", (sha256,))
        database.commit()
    finally: database.close()
    return True

def save_analysis(filename: str, sha256: str, report: dict[str, Any], workspace_id: str) -> str:
    analysis_id, created_at = str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(); database, postgres = connection()
    try:
        execute(database, postgres, "INSERT INTO analyses (id, filename, sha256, status, created_at, report_json, workspace_id) VALUES (?, ?, ?, ?, ?, ?, ?)", (analysis_id, filename, sha256, "COMPLETED", created_at, json.dumps(report), workspace_id))
        for session in report.get("sessions", []):
            session_id = str(uuid.uuid4()); execute(database, postgres, "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)", (session_id, analysis_id, session["session_id"], session["protocol"], session["transition"], session["risk_score"], session["confidence"]))
            for item in session.get("evidence", []): execute(database, postgres, "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (str(uuid.uuid4()), session_id, item["source"], item["field"], item["value"], item.get("frame"), item.get("timestamp"), item.get("raw_value"), item.get("derived_value"), item["confidence"]))
        for finding in report.get("findings", []): execute(database, postgres, "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?)", (str(uuid.uuid4()), analysis_id, finding.get("session"), finding["rule"], finding["severity"], finding["title"], finding["evidence"]))
        database.commit()
    finally: database.close()
    return analysis_id

def list_analyses(workspace_id: str, limit: int = 50) -> list[dict[str, Any]]:
    database, postgres = connection()
    try: rows = execute(database, postgres, "SELECT id, filename, sha256, status, created_at FROM analyses WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ?", (workspace_id, limit)).fetchall()
    finally: database.close()
    return [dict(row) for row in rows]

def get_analysis(analysis_id: str, workspace_id: str) -> dict[str, Any] | None:
    database, postgres = connection()
    try: row = execute(database, postgres, "SELECT report_json FROM analyses WHERE id = ? AND workspace_id = ?", (analysis_id, workspace_id)).fetchone()
    finally: database.close()
    return json.loads(row["report_json"]) if row else None

def historical_sessions(workspace_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Feature source for anomaly baselines; excludes the analysis currently being processed."""
    database, postgres = connection()
    try: rows = execute(database, postgres, "SELECT report_json FROM analyses WHERE status = ? AND workspace_id = ? ORDER BY created_at DESC LIMIT ?", ("COMPLETED", workspace_id, limit)).fetchall()
    finally: database.close()
    return [session for row in rows for session in json.loads(row["report_json"]).get("sessions", [])]


def create_analysis_job(job_id: str, filename: str, sha256: str, workspace_id: str, requested_by: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat(); database, postgres = connection()
    try:
        execute(database, postgres, "INSERT INTO analysis_jobs (id, filename, sha256, workspace_id, requested_by, status, error, analysis_id, attempt, max_attempts, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (job_id, filename, sha256, workspace_id, requested_by, "QUEUED", None, None, 0, 3, now, now))
        database.commit()
    finally: database.close()
    return {"job_id": job_id, "status": "QUEUED"}


def update_analysis_job(job_id: str, status: str, error: str | None = None, analysis_id: str | None = None, attempt: int | None = None) -> None:
    database, postgres = connection()
    try:
        execute(database, postgres, "UPDATE analysis_jobs SET status = ?, error = ?, analysis_id = COALESCE(?, analysis_id), attempt = COALESCE(?, attempt), updated_at = ? WHERE id = ?", (status, error, analysis_id, attempt, datetime.now(timezone.utc).isoformat(), job_id))
        database.commit()
    finally: database.close()


def get_analysis_job(job_id: str, workspace_id: str) -> dict[str, Any] | None:
    database, postgres = connection()
    try: row = execute(database, postgres, "SELECT id, filename, sha256, status, error, analysis_id, attempt, max_attempts, created_at, updated_at FROM analysis_jobs WHERE id = ? AND workspace_id = ?", (job_id, workspace_id)).fetchone()
    finally: database.close()
    return dict(row) if row else None


def get_capture_for_analysis(analysis_id: str, workspace_id: str) -> dict[str, str] | None:
    database, postgres = connection()
    try:
        row = execute(database, postgres, "SELECT a.filename, a.sha256, c.storage_path FROM analyses a JOIN captures c ON c.sha256 = a.sha256 JOIN capture_workspaces w ON w.sha256 = c.sha256 WHERE a.id = ? AND a.workspace_id = ? AND w.workspace_id = ?", (analysis_id, workspace_id, workspace_id)).fetchone()
    finally: database.close()
    return dict(row) if row else None
