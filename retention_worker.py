from __future__ import annotations
import argparse, logging, time
from prometheus_client import start_http_server
from config import settings
from observability import RETENTION_LAST_SUCCESS, RETENTION_PURGED, RETENTION_RUNS, configure_json_logging
from storage.repository import audit, capture_workspaces, purge_capture, retention_candidates_all

logger = logging.getLogger("securemailscope.retention")

def run_cycle(dry_run: bool | None = None) -> dict[str, int | bool]:
    preview = settings.retention_dry_run if dry_run is None else dry_run
    candidates = retention_candidates_all(settings.retention_days); purged = failed = 0
    for capture in candidates:
        sha256 = capture["sha256"]
        if preview: RETENTION_PURGED.labels("previewed").inc(); continue
        try:
            for workspace_id in capture_workspaces(sha256):
                purge_capture(sha256, workspace_id)
                audit("CAPTURE_RETENTION_PURGED", sha256, f"retention_days={settings.retention_days}", workspace_id)
            purged += 1; RETENTION_PURGED.labels("purged").inc()
        except Exception:
            failed += 1; RETENTION_PURGED.labels("failed").inc(); logger.exception("retention purge failed", extra={"job_id": sha256})
    status = "success" if failed == 0 else "partial_failure"; RETENTION_RUNS.labels(status, "dry_run" if preview else "enforced").inc()
    if failed == 0: RETENTION_LAST_SUCCESS.set(time.time())
    result = {"candidates": len(candidates), "purged": purged, "failed": failed, "dry_run": preview}; logger.info("retention cycle completed: %s", result); return result

def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--once", action="store_true"); parser.add_argument("--dry-run", action="store_true"); args = parser.parse_args()
    configure_json_logging(); start_http_server(9101)
    while True:
        run_cycle(True if args.dry_run else None)
        if args.once: break
        time.sleep(settings.retention_interval_seconds)

if __name__ == "__main__": main()
