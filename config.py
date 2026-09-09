from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def secret(name: str, default: str = "") -> str:
    file_value = os.environ.get(f"{name}_FILE", "")
    if file_value:
        try: return Path(file_value).read_text(encoding="utf-8").strip()
        except OSError as error: raise RuntimeError(f"Cannot read configured secret file for {name}.") from error
    return os.environ.get(name, default)


def integer(name: str, default: int, minimum: int, maximum: int) -> int:
    try: value = int(os.environ.get(name, str(default)))
    except ValueError as error: raise RuntimeError(f"{name} must be an integer.") from error
    if not minimum <= value <= maximum: raise RuntimeError(f"{name} must be between {minimum} and {maximum}.")
    return value


@dataclass(frozen=True)
class Settings:
    environment: str
    jwt_secret: str
    zeek_token: str
    redis_url: str
    database_url: str
    allowed_origins: tuple[str, ...]
    max_upload_bytes: int
    job_timeout_seconds: int
    zeek_timeout_seconds: int
    retention_days: int
    ca_bundle: str
    retention_interval_seconds: int
    retention_dry_run: bool


def load_settings() -> Settings:
    environment = os.environ.get("SECUREMAILSCOPE_ENV", "development").lower()
    postgres_password = secret("POSTGRES_PASSWORD")
    database_url = os.environ.get("SECUREMAILSCOPE_DATABASE_URL", "")
    if not database_url and postgres_password and os.environ.get("SECUREMAILSCOPE_DATABASE_HOST"):
        database_url = f"postgresql://securemailscope:{postgres_password}@{os.environ['SECUREMAILSCOPE_DATABASE_HOST']}:5432/securemailscope"
    settings = Settings(environment, secret("SECUREMAILSCOPE_JWT_SECRET", "change-this-development-secret"), secret("SECUREMAILSCOPE_ZEEK_TOKEN"), os.environ.get("SECUREMAILSCOPE_REDIS_URL", "redis://127.0.0.1:6379/0"), database_url, tuple(item.strip() for item in os.environ.get("SECUREMAILSCOPE_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if item.strip()), integer("SECUREMAILSCOPE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024, 1024, 1024 * 1024 * 1024), integer("SECUREMAILSCOPE_JOB_TIMEOUT_SECONDS", 600, 30, 3600), integer("SECUREMAILSCOPE_ZEEK_TIMEOUT_SECONDS", 300, 10, 1800), integer("SECUREMAILSCOPE_RETENTION_DAYS", 30, 1, 3650), os.environ.get("SECUREMAILSCOPE_CA_BUNDLE", ""), integer("SECUREMAILSCOPE_RETENTION_INTERVAL_SECONDS", 86400, 300, 604800), os.environ.get("SECUREMAILSCOPE_RETENTION_DRY_RUN", "false").lower() in {"1", "true", "yes"})
    if environment == "production":
        failures = []
        if len(settings.jwt_secret) < 32 or "change-this" in settings.jwt_secret or "replace" in settings.jwt_secret: failures.append("SECUREMAILSCOPE_JWT_SECRET")
        if len(settings.zeek_token) < 32 or "replace" in settings.zeek_token: failures.append("SECUREMAILSCOPE_ZEEK_TOKEN")
        if not settings.database_url.startswith("postgresql://"): failures.append("PostgreSQL configuration")
        if failures: raise RuntimeError("Unsafe production configuration: " + ", ".join(failures))
    return settings


settings = load_settings()
