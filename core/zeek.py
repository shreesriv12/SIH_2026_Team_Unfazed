"""Optional Zeek worker. Uses a local binary or the official Docker image."""
from __future__ import annotations
import json, os, shutil, subprocess
from pathlib import Path

IMAGE = os.environ.get("SECUREMAILSCOPE_ZEEK_IMAGE", "zeek/zeek:latest")

def engine() -> str | None:
    if shutil.which("zeek"): return "local"
    docker = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True)
    return "docker" if docker.returncode == 0 else None

def run_zeek(pcap: Path, output_dir: Path) -> dict[str, list[dict]]:
    mode = engine()
    if mode is None: raise RuntimeError("Zeek is unavailable. Install Zeek or start Docker Desktop to use the Zeek container worker.")
    output_dir.mkdir(parents=True, exist_ok=True)
    if mode == "local":
        command = ["zeek", "-r", str(pcap.resolve()), "LogAscii::use_json=T"]
        subprocess.run(command, cwd=output_dir, check=True, capture_output=True, text=True)
    else:
        command = ["docker", "run", "--rm", "-w", "/output", "-v", f"{pcap.resolve().parent}:/input:ro", "-v", f"{output_dir.resolve()}:/output", IMAGE, "zeek", "-r", f"/input/{pcap.name}", "LogAscii::use_json=T"]
        subprocess.run(command, cwd=output_dir, check=True, capture_output=True, text=True)
    return load_json_logs(output_dir)

def load_json_logs(output_dir: Path) -> dict[str, list[dict]]:
    logs: dict[str, list[dict]] = {}
    for path in output_dir.glob("*.log"):
        try: logs[path.stem] = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except json.JSONDecodeError: logs[path.stem] = []
    return logs
