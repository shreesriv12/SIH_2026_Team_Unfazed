from pathlib import Path

from auth import create_password_reset_token, login, register, reset_password, rotate_refresh_token


def test_refresh_rotation_and_one_time_password_reset(monkeypatch):
    database = Path("tests/.auth-token-test.db"); database.unlink(missing_ok=True)
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_PATH", str(database))
    try:
        issued = register("token-test@example.test", "initial-password-123", "Token test")
        rotated = rotate_refresh_token(issued["refresh_token"])
        assert rotated and rotated["refresh_token"] != issued["refresh_token"]
        assert rotate_refresh_token(issued["refresh_token"]) is None
        reset_token = create_password_reset_token(issued["user_id"])
        assert reset_password(reset_token, "replacement-password-456")
        assert not reset_password(reset_token, "cannot-reuse-password")
        assert login("token-test@example.test", "replacement-password-456")
        assert rotate_refresh_token(rotated["refresh_token"]) is None
    finally: database.unlink(missing_ok=True)
