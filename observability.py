from __future__ import annotations

import contextvars
import json
import logging
import re
import time
import uuid

from prometheus_client import Counter, Gauge, Histogram

request_id_context = contextvars.ContextVar("request_id", default="-")
SENSITIVE = re.compile(r"(?i)(password|authorization|token|secret)=?[^\s,]*")

HTTP_REQUESTS = Counter("securemailscope_http_requests_total", "API requests", ["method", "path", "status"])
HTTP_DURATION = Histogram("securemailscope_http_request_duration_seconds", "API request duration", ["method", "path"])
JOBS = Counter("securemailscope_analysis_jobs_total", "Analysis job outcomes", ["status"])
JOB_DURATION = Histogram("securemailscope_analysis_job_duration_seconds", "Analysis job duration")
QUEUE_DEPTH = Gauge("securemailscope_queue_depth", "Pending analysis jobs")
DATABASE_READY = Gauge("securemailscope_database_ready", "Database readiness")
REDIS_READY = Gauge("securemailscope_redis_ready", "Redis readiness")
ZEEK_READY = Gauge("securemailscope_zeek_ready", "Zeek readiness")
DISK_FREE_BYTES = Gauge("securemailscope_disk_free_bytes", "Free bytes in capture storage")
RETENTION_RUNS = Counter("securemailscope_retention_runs_total", "Retention cycles", ["status", "mode"])
RETENTION_PURGED = Counter("securemailscope_retention_captures_total", "Captures processed by retention", ["result"])
RETENTION_LAST_SUCCESS = Gauge("securemailscope_retention_last_success_timestamp_seconds", "Unix timestamp of the last successful retention cycle")


def safe(value: object) -> str:
    return SENSITIVE.sub(lambda match: match.group(1) + "=[REDACTED]", str(value).replace("\n", " "))[:2000]


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"), "level": record.levelname, "logger": record.name, "message": safe(record.getMessage()), "request_id": getattr(record, "request_id", request_id_context.get())}
        for field in ("method", "path", "status", "duration_ms", "job_id"):
            if hasattr(record, field): payload[field] = getattr(record, field)
        return json.dumps(payload, separators=(",", ":"))


def configure_json_logging() -> None:
    handler = logging.StreamHandler(); handler.setFormatter(JsonFormatter())
    root = logging.getLogger(); root.handlers = [handler]; root.setLevel(logging.INFO)


def valid_request_id(value: str | None) -> str:
    return value if value and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value) else str(uuid.uuid4())


def metric_path(path: str) -> str:
    path = re.sub(r"/[0-9a-fA-F-]{32,64}(?=/|$)", "/{id}", path)
    return re.sub(r"/[0-9a-fA-F]{64}(?=/|$)", "/{sha256}", path)


class Timer:
    def __enter__(self): self.started = time.perf_counter(); return self
    def __exit__(self, *_): self.seconds = time.perf_counter() - self.started
