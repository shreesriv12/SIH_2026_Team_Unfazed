from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import uuid
import logging
import time
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
import jwt
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from redis import Redis
from rq import Queue
from rq import Retry
from rq.job import Job
import json

from core.analyzer import analyze_pcap
from privacy import redact
from storage.repository import audit, create_analysis_job, get_analysis, get_analysis_job, get_capture_for_analysis, historical_sessions, list_analyses, list_audit_events, purge_capture, retention_candidates, save_analysis, store_capture, update_analysis_job
from reports.html_report import render_html_report
from reports.pdf_report import render_pdf_report
from auth import SECRET, change_member_role, create_member, create_password_reset_token, find_login_identity, get_identity, list_members, login, register, reset_password, revoke_refresh_token, rotate_refresh_token
from core.tshark import get_tshark_version
from core.zeek import engine as zeek_engine
from storage.repository import connection
from capture_security import read_capture
from observability import DATABASE_READY, DISK_FREE_BYTES, HTTP_DURATION, HTTP_REQUESTS, QUEUE_DEPTH, REDIS_READY, ZEEK_READY, configure_json_logging, metric_path, request_id_context, valid_request_id
from config import settings

app = FastAPI(
    title="SecureMailScope API",
    version="1.0.0",
    description="Authenticated PCAP analysis for SMTP, IMAP, POP3, TLS, and X.509 evidence.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
configure_json_logging()
logger = logging.getLogger("securemailscope.api")
app.add_middleware(CORSMiddleware, allow_origins=list(settings.allowed_origins), allow_methods=["*"], allow_headers=["*"])
bearer = HTTPBearer()
class Credentials(BaseModel): email: str; password: str; workspace: str = "Default workspace"
class MemberCreate(BaseModel): email: str; password: str; role: str = "ANALYST"
class RoleChange(BaseModel): role: str
class RefreshRequest(BaseModel): refresh_token: str
class PasswordResetConfirm(BaseModel): token: str; password: str
def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> dict:
    try: claims = jwt.decode(credentials.credentials, SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as error: raise HTTPException(401, "Invalid or expired token.") from error
    if claims.get("type") != "access" or not claims.get("sub") or not claims.get("workspace_id"): raise HTTPException(401, "Token is missing identity claims.")
    identity = get_identity(claims["sub"], claims["workspace_id"])
    if not identity: raise HTTPException(401, "User or workspace is no longer active.")
    return {**claims, **identity, "sub": identity["id"]}
def admin(claims: dict = Depends(current_user)) -> dict:
    if claims.get("role") != "ADMIN": raise HTTPException(403, "Admin role required.")
    return claims
def analyst(claims: dict = Depends(current_user)) -> dict:
    if claims.get("role") not in {"ADMIN", "ANALYST"}: raise HTTPException(403, "Analyst or Admin role required.")
    return claims
UPLOADS = Path("data/uploads")

def queue() -> Queue: return Queue("analysis", connection=Redis.from_url(settings.redis_url))

def enforce_rate_limit(scope: str, identity: str, limit: int, seconds: int) -> None:
    key = f"ratelimit:{scope}:{hashlib.sha256(identity.encode()).hexdigest()}"
    try:
        redis = queue().connection; count = redis.incr(key)
        if count == 1: redis.expire(key, seconds)
    except Exception as error: raise HTTPException(503, "Authentication rate limiter is unavailable.") from error
    if count > limit: raise HTTPException(429, "Too many attempts. Try again later.", headers={"Retry-After": str(seconds)})

def enqueue_analysis(path: Path, filename: str, sha256: str, claims: dict, action: str = "ANALYSIS_QUEUED") -> dict[str, str]:
    tracking_id = str(uuid.uuid4())
    create_analysis_job(tracking_id, filename, sha256, claims["workspace_id"], claims["sub"])
    timeout = settings.job_timeout_seconds
    try:
        queue().enqueue("jobs.analyse_job", str(path), filename, sha256, claims["workspace_id"], tracking_id, job_id=tracking_id, job_timeout=timeout, result_ttl=86400, failure_ttl=86400, retry=Retry(max=2, interval=[10, 30]), meta={"workspace_id": claims["workspace_id"], "user_id": claims["sub"], "request_id": request_id_context.get()})
    except Exception as error:
        update_analysis_job(tracking_id, "FAILED", error=f"Queue unavailable: {type(error).__name__}"[:2000])
        raise HTTPException(503, "Analysis queue is unavailable.") from error
    audit(action, tracking_id, f"sha256={sha256}", claims["workspace_id"], claims["sub"])
    return {"job_id": tracking_id, "status": "QUEUED"}

@app.middleware("http")
async def request_observability(request: Request, call_next):
    request_id = valid_request_id(request.headers.get("X-Request-ID")); token = request_id_context.set(request_id); started = time.perf_counter(); status = 500
    try:
        response = await call_next(request); status = response.status_code; response.headers["X-Request-ID"] = request_id
        if request.url.path.startswith("/api/"):
            response.headers["X-API-Version"] = "1"
            if not request.url.path.startswith("/api/v1/"):
                response.headers["Deprecation"] = "true"
                response.headers["Link"] = f'</api/v1{request.url.path[4:]}>; rel="successor-version"'
        return response
    finally:
        duration = time.perf_counter() - started; path = metric_path(request.url.path)
        HTTP_REQUESTS.labels(request.method, path, str(status)).inc(); HTTP_DURATION.labels(request.method, path).observe(duration)
        logger.info("request completed", extra={"method": request.method, "path": path, "status": status, "duration_ms": round(duration * 1000, 2)})
        request_id_context.reset(token)

@app.get("/api/health")
def health() -> dict:
    checks = {}
    try: checks["tshark"] = get_tshark_version()
    except Exception as error: checks["tshark"] = f"UNAVAILABLE: {error}"
    checks["zeek"] = zeek_engine() or "UNAVAILABLE"
    try:
        database, postgres = connection(); database.close(); checks["database"] = "POSTGRESQL" if postgres else "SQLITE"
    except Exception as error: checks["database"] = f"UNAVAILABLE: {error}"
    try: checks["redis"] = "OK" if queue().connection.ping() else "UNAVAILABLE"
    except Exception as error: checks["redis"] = f"UNAVAILABLE: {error}"
    return {"status": "ok" if all(not str(value).startswith("UNAVAILABLE") for value in checks.values()) else "degraded", "checks": checks}

@app.get("/api/health/live")
def liveness() -> dict: return {"status": "alive"}

@app.get("/api/health/ready")
def readiness() -> Response:
    result = health(); ready = not str(result["checks"].get("database", "")).startswith("UNAVAILABLE") and result["checks"].get("redis") == "OK" and not str(result["checks"].get("tshark", "")).startswith("UNAVAILABLE") and result["checks"].get("zeek") != "UNAVAILABLE"
    return Response(json.dumps({"status": "ready" if ready else "not_ready", "health": result["status"], "checks": result["checks"]}), status_code=200 if ready else 503, media_type="application/json")

@app.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    try:
        database, _ = connection(); database.close(); DATABASE_READY.set(1)
    except Exception: DATABASE_READY.set(0)
    try: redis = queue().connection; REDIS_READY.set(1 if redis.ping() else 0); QUEUE_DEPTH.set(len(queue()))
    except Exception: REDIS_READY.set(0); QUEUE_DEPTH.set(-1)
    try: ZEEK_READY.set(1 if zeek_engine() else 0)
    except Exception: ZEEK_READY.set(0)
    DISK_FREE_BYTES.set(shutil.disk_usage("data").free)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
@app.post("/api/auth/register")
def register_user(credentials: Credentials, request: Request) -> dict:
    enforce_rate_limit("register", request.client.host if request.client else "unknown", 3, 3600)
    if len(credentials.password) < 12: raise HTTPException(400, "Password must be at least 12 characters.")
    try:
        result = register(credentials.email, credentials.password, credentials.workspace)
        audit("ACCOUNT_REGISTERED", result["user_id"], "Initial workspace administrator created", result["workspace_id"], result["user_id"], request.client.host if request.client else None)
        return result
    except Exception as error: raise HTTPException(409, "Email already exists.") from error
@app.post("/api/auth/login")
def login_user(credentials: Credentials, request: Request) -> dict:
    enforce_rate_limit("login", f"{request.client.host if request.client else 'unknown'}:{credentials.email.lower()}", 5, 60)
    result = login(credentials.email, credentials.password)
    if not result:
        identity = find_login_identity(credentials.email)
        if identity: audit("LOGIN_FAILED", identity["id"], "Invalid credentials", identity["workspace_id"], identity["id"], request.client.host if request.client else None)
        raise HTTPException(401, "Invalid email or password.")
    audit("LOGIN_SUCCEEDED", result["user_id"], "Interactive login", result["workspace_id"], result["user_id"], request.client.host if request.client else None)
    return result

@app.post("/api/auth/refresh")
def refresh_session(payload: RefreshRequest) -> dict:
    result = rotate_refresh_token(payload.refresh_token)
    if not result: raise HTTPException(401, "Refresh token is invalid, expired, or already used.")
    return result

@app.post("/api/auth/logout")
def logout_user(request: Request, payload: RefreshRequest | None = None, claims: dict = Depends(current_user)) -> dict:
    if payload: revoke_refresh_token(payload.refresh_token)
    audit("LOGOUT", claims["sub"], "Interactive logout", claims["workspace_id"], claims["sub"], request.client.host if request.client else None)
    return {"status": "ok"}

@app.post("/api/auth/password-reset/confirm")
def password_reset_confirm(payload: PasswordResetConfirm) -> dict:
    if len(payload.password) < 12: raise HTTPException(400, "Password must be at least 12 characters.")
    if not reset_password(payload.token, payload.password): raise HTTPException(400, "Reset token is invalid, expired, or already used.")
    return {"status": "password_changed"}

@app.get("/api/members")
def members(claims: dict = Depends(admin)) -> list[dict]: return list_members(claims["workspace_id"])

@app.post("/api/members", status_code=201)
def invite_member(member: MemberCreate, claims: dict = Depends(admin)) -> dict:
    role = member.role.upper()
    if role not in {"ADMIN", "ANALYST", "VIEWER"}: raise HTTPException(400, "Role must be ADMIN, ANALYST, or VIEWER.")
    if len(member.password) < 12: raise HTTPException(400, "Temporary password must be at least 12 characters.")
    try:
        created = create_member(member.email, member.password, role, claims["workspace_id"])
        audit("MEMBER_CREATED", created["id"], f"role={role}", claims["workspace_id"], claims["sub"])
        return created
    except Exception as error: raise HTTPException(409, "Email already exists.") from error

@app.patch("/api/members/{user_id}")
def update_member(user_id: str, change: RoleChange, claims: dict = Depends(admin)) -> dict:
    role = change.role.upper()
    if role not in {"ADMIN", "ANALYST", "VIEWER"}: raise HTTPException(400, "Role must be ADMIN, ANALYST, or VIEWER.")
    if user_id == claims["sub"] and role != "ADMIN": raise HTTPException(400, "Admins cannot remove their own Admin role.")
    if not change_member_role(user_id, role, claims["workspace_id"]): raise HTTPException(404, "Workspace member not found.")
    audit("MEMBER_ROLE_CHANGED", user_id, f"role={role}", claims["workspace_id"], claims["sub"])
    return {"id": user_id, "role": role}

@app.post("/api/members/{user_id}/password-reset-token")
def member_password_reset_token(user_id: str, claims: dict = Depends(admin)) -> dict:
    identity = get_identity(user_id, claims["workspace_id"])
    if not identity: raise HTTPException(404, "Workspace member not found.")
    token = create_password_reset_token(user_id); audit("PASSWORD_RESET_ISSUED", user_id, "One-time reset token issued", claims["workspace_id"], claims["sub"])
    return {"reset_token": token, "expires_in": 1800}

@app.post("/api/jobs", status_code=202)
async def create_job(file: UploadFile = File(...), claims: dict = Depends(analyst)) -> dict[str, str]:
    content, suffix = await read_capture(file)
    if shutil.disk_usage(".").free < len(content) * 3: raise HTTPException(507, "Insufficient disk space for safe PCAP analysis.")
    sha256, path = store_capture(content, suffix, claims["workspace_id"], file.filename)
    return enqueue_analysis(path, file.filename, sha256, claims)

@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, claims: dict = Depends(current_user)) -> dict:
    job = get_analysis_job(job_id, claims["workspace_id"])
    if not job: raise HTTPException(404, "Job not found.")
    result = get_analysis(job["analysis_id"], claims["workspace_id"]) if job["status"] == "COMPLETED" and job.get("analysis_id") else None
    return {"job_id": job["id"], "status": job["status"], "result": result, "error": job.get("error"), "attempt": job.get("attempt", 0), "max_attempts": job.get("max_attempts", 3), "created_at": job["created_at"], "updated_at": job["updated_at"]}

@app.post("/api/analyse")
async def analyse(file: UploadFile = File(...), claims: dict = Depends(analyst)) -> dict:
    content, suffix = await read_capture(file)
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(content); path = Path(temp.name)
    try:
        result = redact(analyze_pcap(path).as_dict())
        result["file"] = file.filename
        result["sha256"] = hashlib.sha256(content).hexdigest()
        result["analysis_id"] = save_analysis(file.filename, result["sha256"], result, claims["workspace_id"])
        audit("ANALYSIS_COMPLETED", result["analysis_id"], f"sha256={result['sha256']}", claims["workspace_id"], claims["sub"])
        return result
    except Exception as error: raise HTTPException(422, str(error)) from error
    finally: os.unlink(path)

@app.get("/api/analyses")
def analyses(claims: dict = Depends(current_user)) -> list[dict]:
    return list_analyses(claims["workspace_id"])

@app.get("/api/audit-events")
def audit_events(action: str | None = None, actor_id: str | None = None, from_date: str | None = None, to_date: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=100), claims: dict = Depends(admin)) -> dict:
    return list_audit_events(claims["workspace_id"], action, actor_id, from_date, to_date, page, page_size)

@app.get("/api/analyses/{analysis_id}")
def analysis_history(analysis_id: str, claims: dict = Depends(current_user)) -> dict:
    result = get_analysis(analysis_id, claims["workspace_id"])
    if result is None: raise HTTPException(404, "Analysis not found.")
    return result

@app.post("/api/analyses/{analysis_id}/rerun", status_code=202)
def rerun_analysis(analysis_id: str, claims: dict = Depends(analyst)) -> dict[str, str]:
    capture = get_capture_for_analysis(analysis_id, claims["workspace_id"])
    if not capture: raise HTTPException(404, "Analysis or retained capture not found.")
    path = Path(capture["storage_path"])
    if not path.is_file(): raise HTTPException(410, "The retained capture is no longer available.")
    return enqueue_analysis(path, capture["filename"], capture["sha256"], claims, "ANALYSIS_RERUN_QUEUED")

@app.get("/api/retention/candidates")
def retention_preview(claims: dict = Depends(admin)) -> dict:
    days = settings.retention_days
    return {"retention_days": days, "captures": retention_candidates(days, claims["workspace_id"])}

@app.delete("/api/retention/candidates/{sha256}")
def retention_purge(sha256: str, claims: dict = Depends(admin)) -> dict:
    if not purge_capture(sha256, claims["workspace_id"]): raise HTTPException(404, "Capture not found.")
    audit("CAPTURE_PURGED", sha256, "Explicit retention purge", claims["workspace_id"], claims["sub"])
    return {"sha256": sha256, "status": "PURGED"}

@app.post("/api/report/json")
async def json_report(file: UploadFile = File(...), claims: dict = Depends(analyst)) -> Response:
    content, suffix = await read_capture(file)
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(content); path = Path(temp.name)
    try:
        result = redact(analyze_pcap(path, historical_sessions(claims["workspace_id"])).as_dict())
        result["file"] = file.filename
        audit("REPORT_DOWNLOADED", hashlib.sha256(content).hexdigest(), "format=JSON", claims["workspace_id"], claims["sub"])
        return Response(json.dumps(result, indent=2), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{Path(file.filename).stem}-report.json"'})
    finally: os.unlink(path)

@app.post("/api/report/html")
async def html_report(file: UploadFile = File(...), claims: dict = Depends(analyst)) -> Response:
    content, suffix = await read_capture(file)
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
        temp.write(content); path = Path(temp.name)
    try:
        result = redact(analyze_pcap(path, historical_sessions(claims["workspace_id"])).as_dict()); result["file"] = file.filename; result["sha256"] = hashlib.sha256(content).hexdigest()
        audit("REPORT_DOWNLOADED", result["sha256"], "format=HTML", claims["workspace_id"], claims["sub"])
        return Response(render_html_report(result), media_type="text/html", headers={"Content-Disposition": f'attachment; filename="{Path(file.filename).stem}-report.html"'})
    finally: os.unlink(path)

@app.post("/api/report/pdf")
async def pdf_report(file: UploadFile = File(...), claims: dict = Depends(analyst)) -> Response:
    content, suffix = await read_capture(file)
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp: temp.write(content); path = Path(temp.name)
    try:
        result = redact(analyze_pcap(path, historical_sessions(claims["workspace_id"])).as_dict()); result["file"] = file.filename; result["sha256"] = hashlib.sha256(content).hexdigest()
        audit("REPORT_DOWNLOADED", result["sha256"], "format=PDF", claims["workspace_id"], claims["sub"])
        return Response(render_pdf_report(result), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{Path(file.filename).stem}-report.pdf"'})
    finally: os.unlink(path)


def register_versioned_routes() -> None:
    """Publish v1 routes while retaining hidden legacy aliases for the frontend."""
    legacy_routes = [
        route for route in list(app.routes)
        if isinstance(route, APIRoute) and route.path.startswith("/api/")
    ]
    for route in legacy_routes:
        route.include_in_schema = False
        app.add_api_route(
            f"/api/v1{route.path[4:]}",
            route.endpoint,
            methods=route.methods,
            response_model=route.response_model,
            status_code=route.status_code,
            tags=route.tags,
            summary=route.summary,
            description=route.description,
            response_description=route.response_description,
            responses=route.responses,
            deprecated=route.deprecated,
            name=f"v1_{route.name}",
        )


register_versioned_routes()
