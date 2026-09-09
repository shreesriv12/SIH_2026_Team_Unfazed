from pathlib import Path

from storage.repository import audit, create_analysis_job, get_analysis, get_analysis_job, list_analyses, list_audit_events, save_analysis, store_capture, update_analysis_job


def test_analysis_history_persists_normalized_records(monkeypatch):
    database_path = Path("tests/.repository-test.db")
    if database_path.exists(): database_path.unlink()
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_PATH", str(database_path))
    report = {"sessions": [{"session_id": "stream-1", "protocol": "SMTP", "transition": "STARTTLS_TO_TLS", "risk_score": 0, "confidence": "HIGH", "evidence": [{"source": "tshark", "field": "frame.number", "value": "1", "confidence": "DIRECT"}]}], "findings": []}
    try:
        analysis_id = save_analysis("sample.pcapng", "a" * 64, report, "workspace-a")
        assert get_analysis(analysis_id, "workspace-a") == report
        assert get_analysis(analysis_id, "workspace-b") is None
        assert list_analyses("workspace-a")[0]["filename"] == "sample.pcapng"
        assert list_analyses("workspace-b") == []
    finally:
        if database_path.exists(): database_path.unlink()

def test_capture_storage_is_content_addressed(monkeypatch):
    database_path = Path("tests/.capture-test.db")
    if database_path.exists(): database_path.unlink()
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_PATH", str(database_path))
    try:
        first_sha, first_path = store_capture(b"pcap-bytes", ".pcapng", "workspace-a")
        second_sha, second_path = store_capture(b"pcap-bytes", ".pcapng", "workspace-a")
        assert first_sha == second_sha and first_path == second_path and first_path.exists()
    finally:
        if database_path.exists(): database_path.unlink()
        if 'first_path' in locals() and first_path.exists(): first_path.unlink()


def test_job_status_persists_without_redis(monkeypatch):
    database_path = Path("tests/.job-test.db")
    if database_path.exists(): database_path.unlink()
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_PATH", str(database_path))
    try:
        create_analysis_job("job-1", "sample.pcapng", "b" * 64, "workspace-a", "user-1")
        assert get_analysis_job("job-1", "workspace-a")["status"] == "QUEUED"
        update_analysis_job("job-1", "RUNNING")
        assert get_analysis_job("job-1", "workspace-a")["status"] == "RUNNING"
        update_analysis_job("job-1", "FAILED", error="parser failed")
        assert get_analysis_job("job-1", "workspace-a")["error"] == "parser failed"
        update_analysis_job("job-1", "RETRYING", error="temporary failure", attempt=1)
        retrying = get_analysis_job("job-1", "workspace-a")
        assert retrying["status"] == "RETRYING"
        assert retrying["attempt"] == 1
        assert retrying["max_attempts"] == 3
        assert get_analysis_job("job-1", "workspace-b") is None
    finally:
        if database_path.exists(): database_path.unlink()


def test_audit_events_are_workspace_scoped_and_filtered(monkeypatch):
    database_path = Path("tests/.audit-test.db")
    if database_path.exists(): database_path.unlink()
    monkeypatch.setenv("SECUREMAILSCOPE_DATABASE_PATH", str(database_path))
    try:
        audit("LOGIN_SUCCEEDED", "user-1", "Interactive login", "workspace-a", "user-1", "127.0.0.1")
        audit("REPORT_DOWNLOADED", "capture-1", "format=PDF", "workspace-b", "user-2")
        result = list_audit_events("workspace-a", action="LOGIN_SUCCEEDED")
        assert result["total"] == 1
        assert result["items"][0]["actor_id"] == "user-1"
        assert list_audit_events("workspace-b", actor_id="user-1")["total"] == 0
    finally:
        if database_path.exists(): database_path.unlink()
