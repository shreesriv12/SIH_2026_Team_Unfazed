"""Assign existing analyses to the Team Unfazed workspace. Safe to run repeatedly."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from storage.repository import connection, execute

WORKSPACE = "Team Unfazed"
database, postgres = connection()
try:
    try: execute(database, postgres, "ALTER TABLE analyses ADD COLUMN workspace_id TEXT", ())
    except Exception: pass
    row = execute(database, postgres, "SELECT id FROM workspaces WHERE name = ? LIMIT 1", (WORKSPACE,)).fetchone()
    if not row:
        raise RuntimeError("Create an account with workspace name 'Team Unfazed' first.")
    workspace_id = row["id"]
    execute(database, postgres, "UPDATE analyses SET workspace_id = ? WHERE workspace_id IS NULL", (workspace_id,))
    database.commit()
    print(f"Migrated existing analyses to workspace: {WORKSPACE}")
finally:
    database.close()
