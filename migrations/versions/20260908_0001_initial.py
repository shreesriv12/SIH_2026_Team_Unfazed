"""Baseline persistent SecureMailScope schema."""
from alembic import op

revision = "20260908_0001"
down_revision = None
branch_labels = None
depends_on = None

TABLES = [
"CREATE TABLE IF NOT EXISTS analyses (id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, report_json TEXT NOT NULL, workspace_id TEXT)",
"CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE, session_key TEXT NOT NULL, protocol TEXT NOT NULL, transition TEXT NOT NULL, risk_score INTEGER NOT NULL, confidence TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE, session_key TEXT, rule_id TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, evidence TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, source TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, frame TEXT, timestamp TEXT, raw_value TEXT, derived_value TEXT, confidence TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS captures (sha256 TEXT PRIMARY KEY, storage_path TEXT NOT NULL, byte_size INTEGER NOT NULL, created_at TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS capture_workspaces (sha256 TEXT NOT NULL REFERENCES captures(sha256), workspace_id TEXT NOT NULL, PRIMARY KEY (sha256, workspace_id))",
"CREATE TABLE IF NOT EXISTS custody_events (id TEXT PRIMARY KEY, sha256 TEXT NOT NULL REFERENCES captures(sha256), action TEXT NOT NULL, created_at TEXT NOT NULL, detail TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS audit_events (id TEXT PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL, detail TEXT NOT NULL, workspace_id TEXT, actor_id TEXT, ip_address TEXT)",
"CREATE TABLE IF NOT EXISTS workspaces (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, workspace_id TEXT NOT NULL REFERENCES workspaces(id), created_at TEXT NOT NULL)",
"CREATE TABLE IF NOT EXISTS analysis_jobs (id TEXT PRIMARY KEY, filename TEXT NOT NULL, sha256 TEXT NOT NULL, workspace_id TEXT NOT NULL, requested_by TEXT NOT NULL, status TEXT NOT NULL, error TEXT, analysis_id TEXT, attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
]

def upgrade() -> None:
    for statement in TABLES: op.execute(statement)
    op.execute("ALTER TABLE analysis_jobs ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 0")
    op.execute("ALTER TABLE analysis_jobs ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 3")

def downgrade() -> None:
    for table in ("analysis_jobs", "users", "workspaces", "audit_events", "custody_events", "capture_workspaces", "captures", "evidence", "findings", "sessions", "analyses"):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
