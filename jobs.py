from __future__ import annotations
import hashlib
import logging
import time
from pathlib import Path
from core.analyzer import analyze_pcap
from privacy import redact
from storage.repository import audit, historical_sessions, record_custody, save_analysis, update_analysis_job
from observability import JOB_DURATION, JOBS, request_id_context
from rq import get_current_job

logger = logging.getLogger("securemailscope.worker")

def analyse_job(path_value: str, filename: str, sha256: str, workspace_id: str, tracking_id: str | None = None) -> dict:
    started = time.perf_counter(); rq_job = get_current_job(); token = request_id_context.set(str((rq_job.meta if rq_job else {}).get("request_id", tracking_id or "-")))
    path = Path(path_value)
    attempt = int((rq_job.meta if rq_job else {}).get("attempt", 0)) + 1
    if rq_job:
        rq_job.meta["attempt"] = attempt
        rq_job.save_meta()
    if tracking_id: update_analysis_job(tracking_id, "RUNNING", attempt=attempt)
    logger.info("analysis job started", extra={"job_id": tracking_id or "legacy"})
    try:
        result = redact(analyze_pcap(path, historical_sessions(workspace_id)).as_dict())
        result["file"] = filename; result["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        result["analysis_id"] = save_analysis(filename, result["sha256"], result, workspace_id); record_custody(sha256, "ANALYSED", result["analysis_id"])
        if tracking_id: update_analysis_job(tracking_id, "COMPLETED", analysis_id=result["analysis_id"])
        audit("ANALYSIS_JOB_COMPLETED", result["analysis_id"], f"job_id={tracking_id or 'legacy'} sha256={sha256}", workspace_id)
        JOBS.labels("completed").inc(); logger.info("analysis job completed", extra={"job_id": tracking_id or "legacy"})
        return result
    except Exception as error:
        record_custody(sha256, "ANALYSIS_FAILED", type(error).__name__)
        will_retry = bool(rq_job and (rq_job.retries_left or 0) > 0)
        status = "RETRYING" if will_retry else "FAILED"
        if tracking_id: update_analysis_job(tracking_id, status, error=f"{type(error).__name__}: {error}"[:2000], attempt=attempt)
        audit("ANALYSIS_JOB_RETRYING" if will_retry else "ANALYSIS_JOB_FAILED", tracking_id or sha256, f"attempt={attempt} error={type(error).__name__}", workspace_id)
        JOBS.labels("failed").inc(); logger.exception("analysis job failed", extra={"job_id": tracking_id or "legacy"})
        raise
    finally:
        JOB_DURATION.observe(time.perf_counter() - started); request_id_context.reset(token)
