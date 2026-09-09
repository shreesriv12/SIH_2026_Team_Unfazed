"""Optional Zeek worker. Uses a local binary or the official Docker image."""
from __future__ import annotations
import json, os, shutil, subprocess
import urllib.error
import urllib.request
from pathlib import Path
from observability import request_id_context
from config import settings

IMAGE = os.environ.get("SECUREMAILSCOPE_ZEEK_IMAGE", "zeek/zeek:latest")
REMOTE_URL = os.environ.get("SECUREMAILSCOPE_ZEEK_URL", "").rstrip("/")
REMOTE_TOKEN = settings.zeek_token

def _remote_request(path: str, payload: dict | None = None, timeout: int = 5) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(f"{REMOTE_URL}{path}", data=body, headers={"X-Zeek-Token": REMOTE_TOKEN, "X-Request-ID": request_id_context.get(), "Content-Type": "application/json"}, method="POST" if body is not None else "GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())

def engine() -> str | None:
    if REMOTE_URL and REMOTE_TOKEN:
        try:
            if _remote_request("/health").get("status") == "ok": return "remote"
        except (OSError, ValueError, urllib.error.URLError):
            pass
    if shutil.which("zeek"): return "local"
    # Backend containers deliberately do not contain the Docker CLI or mount the
    # host Docker socket. Zeek is optional, so discovery must not break health
    # checks when neither execution mode is present.
    if not shutil.which("docker"):
        return None
    try:
        docker = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return "docker" if docker.returncode == 0 else None

def run_zeek(pcap: Path, output_dir: Path) -> dict[str, list[dict]]:
    mode = engine()
    if mode is None: raise RuntimeError("Zeek is unavailable. Install Zeek or start Docker Desktop to use the Zeek container worker.")
    if mode == "remote":
        try:
            response = _remote_request("/analyse", {"capture": pcap.name}, timeout=settings.zeek_timeout_seconds + 10)
            return response.get("logs", {})
        except (OSError, ValueError, urllib.error.URLError) as error:
            raise RuntimeError(f"Remote Zeek analysis failed: {error}") from error
    output_dir.mkdir(parents=True, exist_ok=True)
    if mode == "local":
        command = ["zeek", "-r", str(pcap.resolve()), "LogAscii::use_json=T"]
        subprocess.run(command, cwd=output_dir, check=True, capture_output=True, text=True, timeout=300)
    else:
        command = ["docker", "run", "--rm", "-w", "/output", "-v", f"{pcap.resolve().parent}:/input:ro", "-v", f"{output_dir.resolve()}:/output", IMAGE, "zeek", "-r", f"/input/{pcap.name}", "LogAscii::use_json=T"]
        subprocess.run(command, cwd=output_dir, check=True, capture_output=True, text=True, timeout=300)
    return load_json_logs(output_dir)

def load_json_logs(output_dir: Path) -> dict[str, list[dict]]:
    logs: dict[str, list[dict]] = {}
    for path in output_dir.glob("*.log"):
        try: logs[path.stem] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except json.JSONDecodeError: logs[path.stem] = []
    return logs
