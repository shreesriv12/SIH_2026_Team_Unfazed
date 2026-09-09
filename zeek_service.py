"""Small internal-only HTTP boundary for the isolated Zeek process."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CAPTURE_ROOT = Path(os.environ.get("SECUREMAILSCOPE_CAPTURE_ROOT", "/data/captures")).resolve()
def read_secret(name: str) -> str:
    path = os.environ.get(f"{name}_FILE", "")
    return Path(path).read_text(encoding="utf-8").strip() if path else os.environ.get(name, "")

TOKEN = read_secret("SECUREMAILSCOPE_ZEEK_TOKEN")
ZEEK = os.environ.get("SECUREMAILSCOPE_ZEEK_BINARY", "/usr/local/zeek/bin/zeek")
TIMEOUT = int(os.environ.get("SECUREMAILSCOPE_ZEEK_TIMEOUT_SECONDS", "300"))
MAX_RECORDS = int(os.environ.get("SECUREMAILSCOPE_ZEEK_MAX_RECORDS_PER_LOG", "10000"))
MAX_REQUEST_BYTES = 4096
analysis_slot = threading.BoundedSemaphore(1)
metrics = {"requests": 0, "analyses": 0, "failures": 0, "duration": 0.0}


def zeek_version() -> str:
    result = subprocess.run([ZEEK, "--version"], capture_output=True, text=True, timeout=5, check=True)
    return (result.stdout or result.stderr).strip()


def capture_path(name: str) -> Path:
    if not name or Path(name).name != name or Path(name).suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise ValueError("Invalid capture name.")
    path = (CAPTURE_ROOT / name).resolve()
    if CAPTURE_ROOT not in path.parents or not path.is_file():
        raise FileNotFoundError("Capture not found.")
    return path


def load_logs(directory: Path) -> dict[str, list[dict]]:
    logs: dict[str, list[dict]] = {}
    for path in directory.glob("*.log"):
        records = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:MAX_RECORDS]:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        logs[path.stem] = records
    return logs


class Handler(BaseHTTPRequestHandler):
    server_version = "SecureMailScope-Zeek/1.0"

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authenticated(self) -> bool:
        return bool(TOKEN) and self.headers.get("X-Zeek-Token") == TOKEN

    def do_GET(self) -> None:
        metrics["requests"] += 1
        if self.path == "/metrics":
            body = (f"securemailscope_zeek_requests_total {metrics['requests']}\n"
                    f"securemailscope_zeek_analyses_total {metrics['analyses']}\n"
                    f"securemailscope_zeek_failures_total {metrics['failures']}\n"
                    f"securemailscope_zeek_analysis_duration_seconds_sum {metrics['duration']}\n").encode()
            self.send_response(200); self.send_header("Content-Type", "text/plain; version=0.0.4"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        if self.path != "/health":
            return self.send_json(404, {"error": "Not found."})
        if not self.authenticated():
            return self.send_json(401, {"error": "Unauthorized."})
        try:
            self.send_json(200, {"status": "ok", "engine": zeek_version()})
        except Exception:
            self.send_json(503, {"status": "unavailable"})

    def do_POST(self) -> None:
        metrics["requests"] += 1
        if self.path != "/analyse": return self.send_json(404, {"error": "Not found."})
        if not self.authenticated(): return self.send_json(401, {"error": "Unauthorized."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size < 1 or size > MAX_REQUEST_BYTES: return self.send_json(413, {"error": "Invalid request size."})
            name = str(json.loads(self.rfile.read(size)).get("capture", ""))
            capture = capture_path(name)
        except (ValueError, json.JSONDecodeError):
            return self.send_json(400, {"error": "Invalid request."})
        except FileNotFoundError:
            return self.send_json(404, {"error": "Capture not found."})
        if not analysis_slot.acquire(blocking=False):
            return self.send_json(429, {"error": "Zeek worker is busy."})
        started = time.perf_counter()
        try:
            with tempfile.TemporaryDirectory(prefix="securemailscope-zeek-") as output:
                result = subprocess.run([ZEEK, "-r", str(capture), "LogAscii::use_json=T"], cwd=output, capture_output=True, text=True, timeout=TIMEOUT, check=False)
                if result.returncode != 0:
                    metrics["failures"] += 1
                    return self.send_json(422, {"error": "Zeek could not parse the capture.", "detail": result.stderr[-1000:]})
                metrics["analyses"] += 1
                self.send_json(200, {"logs": load_logs(Path(output))})
        except subprocess.TimeoutExpired:
            metrics["failures"] += 1
            self.send_json(504, {"error": "Zeek analysis timed out."})
        finally:
            metrics["duration"] += time.perf_counter() - started
            analysis_slot.release()

    def log_message(self, format: str, *args: object) -> None:
        print(json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": "INFO", "logger": "securemailscope.zeek", "message": format % args, "request_id": self.headers.get("X-Request-ID", "-")}, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
