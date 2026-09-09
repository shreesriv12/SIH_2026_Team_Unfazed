from __future__ import annotations
import hashlib, hmac, os, secrets, time
import jwt
import uuid
from datetime import datetime, timedelta, timezone
from storage.repository import connection, execute
from config import settings

SECRET = settings.jwt_secret

def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
    return f"{salt}${digest}"

def verify_password(password: str, stored: str) -> bool:
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)

def issue_token(user_id: str, role: str, workspace_id: str) -> str:
    return jwt.encode({"sub": user_id, "role": role, "workspace_id": workspace_id, "type": "access", "exp": int(time.time()) + 900}, SECRET, algorithm="HS256")

def _token_hash(token: str) -> str: return hashlib.sha256(token.encode()).hexdigest()

def issue_refresh_token(user_id: str, workspace_id: str) -> str:
    token = secrets.token_urlsafe(48); now = datetime.now(timezone.utc); database, postgres = connection()
    try:
        execute(database, postgres, "INSERT INTO refresh_tokens VALUES (?, ?, ?, ?, ?, ?)", (_token_hash(token), user_id, workspace_id, (now + timedelta(days=7)).isoformat(), None, now.isoformat())); database.commit()
    finally: database.close()
    return token

def token_response(user_id: str, role: str, workspace_id: str) -> dict:
    return {"access_token": issue_token(user_id, role, workspace_id), "refresh_token": issue_refresh_token(user_id, workspace_id), "token_type": "bearer", "expires_in": 900, "role": role, "workspace_id": workspace_id, "user_id": user_id}

def rotate_refresh_token(token: str) -> dict | None:
    now = datetime.now(timezone.utc).isoformat(); database, postgres = connection()
    try:
        row = execute(database, postgres, "SELECT user_id, workspace_id FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?", (_token_hash(token), now)).fetchone()
        if not row: return None
        execute(database, postgres, "UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ?", (now, _token_hash(token))); database.commit()
    finally: database.close()
    identity = get_identity(row["user_id"], row["workspace_id"])
    return token_response(identity["id"], identity["role"], identity["workspace_id"]) if identity else None

def revoke_refresh_token(token: str) -> None:
    database, postgres = connection()
    try: execute(database, postgres, "UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL", (datetime.now(timezone.utc).isoformat(), _token_hash(token))); database.commit()
    finally: database.close()

def create_password_reset_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32); now = datetime.now(timezone.utc); database, postgres = connection()
    try: execute(database, postgres, "INSERT INTO password_reset_tokens VALUES (?, ?, ?, ?, ?)", (_token_hash(token), user_id, (now + timedelta(minutes=30)).isoformat(), None, now.isoformat())); database.commit()
    finally: database.close()
    return token

def reset_password(token: str, password: str) -> bool:
    now = datetime.now(timezone.utc).isoformat(); database, postgres = connection()
    try:
        row = execute(database, postgres, "SELECT user_id FROM password_reset_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?", (_token_hash(token), now)).fetchone()
        if not row: return False
        execute(database, postgres, "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), row["user_id"])); execute(database, postgres, "UPDATE password_reset_tokens SET used_at = ? WHERE token_hash = ?", (now, _token_hash(token))); execute(database, postgres, "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (now, row["user_id"])); database.commit(); return True
    finally: database.close()

def register(email: str, password: str, workspace: str) -> dict:
    database, postgres = connection(); user_id, workspace_id = str(uuid.uuid4()), str(uuid.uuid4()); now = datetime.now(timezone.utc).isoformat()
    try:
        execute(database, postgres, "INSERT INTO workspaces VALUES (?, ?, ?)", (workspace_id, workspace, now)); execute(database, postgres, "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", (user_id, email.lower(), hash_password(password), "ADMIN", workspace_id, now)); database.commit()
    finally: database.close()
    return token_response(user_id, "ADMIN", workspace_id)

def login(email: str, password: str) -> dict | None:
    database, postgres = connection()
    try: user = execute(database, postgres, "SELECT id, password_hash, role, workspace_id FROM users WHERE email = ?", (email.lower(),)).fetchone()
    finally: database.close()
    if not user or not verify_password(password, user["password_hash"]): return None
    return token_response(user["id"], user["role"], user["workspace_id"])

def find_login_identity(email: str) -> dict | None:
    database, postgres = connection()
    try: row = execute(database, postgres, "SELECT id, workspace_id FROM users WHERE email = ?", (email.lower(),)).fetchone()
    finally: database.close()
    return dict(row) if row else None

def list_members(workspace_id: str) -> list[dict]:
    database, postgres = connection()
    try: rows = execute(database, postgres, "SELECT id, email, role, created_at FROM users WHERE workspace_id = ? ORDER BY created_at", (workspace_id,)).fetchall()
    finally: database.close()
    return [dict(row) for row in rows]

def create_member(email: str, password: str, role: str, workspace_id: str) -> dict:
    user_id, now = str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(); database, postgres = connection()
    try:
        execute(database, postgres, "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", (user_id, email.lower(), hash_password(password), role, workspace_id, now)); database.commit()
    finally: database.close()
    return {"id": user_id, "email": email.lower(), "role": role, "created_at": now}

def change_member_role(user_id: str, role: str, workspace_id: str) -> bool:
    database, postgres = connection()
    try:
        cursor = execute(database, postgres, "UPDATE users SET role = ? WHERE id = ? AND workspace_id = ?", (role, user_id, workspace_id)); database.commit()
        return cursor.rowcount == 1
    finally: database.close()

def get_identity(user_id: str, workspace_id: str) -> dict | None:
    database, postgres = connection()
    try: row = execute(database, postgres, "SELECT id, email, role, workspace_id FROM users WHERE id = ? AND workspace_id = ?", (user_id, workspace_id)).fetchone()
    finally: database.close()
    return dict(row) if row else None
