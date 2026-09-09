import pytest
from pathlib import Path

from config import load_settings, secret


def test_secret_file_takes_precedence(monkeypatch):
    path = Path("tests/.config-secret-test.txt")
    try:
        path.write_text("from-file\n", encoding="utf-8")
        monkeypatch.setenv("EXAMPLE_SECRET", "from-environment")
        monkeypatch.setenv("EXAMPLE_SECRET_FILE", str(path))
        assert secret("EXAMPLE_SECRET") == "from-file"
    finally:
        path.unlink(missing_ok=True)


def test_production_rejects_placeholder_secrets(monkeypatch):
    monkeypatch.setenv("SECUREMAILSCOPE_ENV", "production")
    monkeypatch.setenv("SECUREMAILSCOPE_JWT_SECRET", "change-this-development-secret")
    monkeypatch.setenv("SECUREMAILSCOPE_ZEEK_TOKEN", "replace-this-zeek-token")
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_URL", "postgresql://example")
    with pytest.raises(RuntimeError, match="Unsafe production configuration"):
        load_settings()


def test_bounded_numeric_configuration(monkeypatch):
    monkeypatch.setenv("SECUREMAILSCOPE_MAX_UPLOAD_BYTES", "0")
    with pytest.raises(RuntimeError, match="SECUREMAILSCOPE_MAX_UPLOAD_BYTES"):
        load_settings()
