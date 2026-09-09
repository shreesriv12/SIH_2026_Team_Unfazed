"""Refresh-token rotation and one-time password resets."""
from alembic import op

revision = "20260908_0002"
down_revision = "20260908_0001"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.execute("CREATE TABLE IF NOT EXISTS refresh_tokens (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, workspace_id TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, created_at TEXT NOT NULL)")
    op.execute("CREATE TABLE IF NOT EXISTS password_reset_tokens (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT NOT NULL)")

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS password_reset_tokens")
    op.execute("DROP TABLE IF EXISTS refresh_tokens")
