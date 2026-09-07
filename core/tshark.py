from __future__ import annotations

import json
import csv
import io
import shutil
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_WINDOWS_TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")


def get_tshark_path() -> str:
    return shutil.which("tshark") or str(DEFAULT_WINDOWS_TSHARK) if DEFAULT_WINDOWS_TSHARK.exists() else _missing()


def _missing() -> str:
    raise FileNotFoundError("TShark was not found in PATH or C:\\Program Files\\Wireshark\\tshark.exe")


def get_tshark_version() -> str:
    completed = subprocess.run([get_tshark_path(), "--version"], capture_output=True, text=True, check=True)
    return completed.stdout.splitlines()[0].strip()


def run_tshark_json(pcap_path: Path) -> list[dict[str, Any]]:
    pcap_path = pcap_path.resolve()
    if not pcap_path.is_file(): raise FileNotFoundError(pcap_path)
    command = [get_tshark_path(), "-r", str(pcap_path), "-d", "tcp.port==2525,smtp", "-d", "tcp.port==2526,smtp", "-d", "tcp.port==2527,smtp", "-d", "tcp.port==2528,smtp", "-d", "tcp.port==2529,smtp", "-d", "tcp.port==2530,smtp", "-d", "tcp.port==2143,imap", "-d", "tcp.port==2144,imap", "-d", "tcp.port==2110,pop", "-d", "tcp.port==2111,pop", "-Y", "smtp || imap || pop || tls", "-T", "json"]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0: raise RuntimeError(f"TShark failed:\n{completed.stderr.strip()}")
    return json.loads(completed.stdout or "[]")


def extract_email_tls_events(pcap_path: Path) -> list[dict[str, Any]]:
    """Extract a small, stable evidence table rather than depending on dissector-tree JSON."""
    fields = ["frame.number", "frame.time_epoch", "tcp.stream", "tcp.srcport", "tcp.dstport", "frame.protocols", "smtp.req.command", "smtp.command_line", "smtp.response", "imap.request.command", "imap.response.status", "pop.request.command", "pop.response", "pop.response.indicator", "tls.handshake.certificate",
              "tls.record.version", "tls.handshake.version", "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite"]
    command = [get_tshark_path(), "-r", str(pcap_path.resolve()), "-d", "tcp.port==2525,smtp", "-d", "tcp.port==2526,smtp", "-d", "tcp.port==2527,smtp", "-d", "tcp.port==2528,smtp", "-d", "tcp.port==2529,smtp", "-d", "tcp.port==2530,smtp", "-d", "tcp.port==2143,imap", "-d", "tcp.port==2144,imap", "-d", "tcp.port==2110,pop", "-d", "tcp.port==2111,pop", "-Y", "tcp && (smtp || imap || pop || tls)",
               "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d"]
    for field in fields: command.extend(["-e", field])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0: raise RuntimeError(f"TShark failed:\n{completed.stderr.strip()}")
    events = []
    for row in csv.DictReader(io.StringIO(completed.stdout), delimiter="\t"):
        protocols = row.get("frame.protocols", "").lower()
        protocol = "SMTP" if "smtp" in protocols else "IMAP" if "imap" in protocols else "POP3" if "pop" in protocols else "TLS_UNCLASSIFIED"
        events.append({"frame": row.get("frame.number") or "?", "protocol": protocol,
                       "timestamp": row.get("frame.time_epoch"),
                       "stream": row.get("tcp.stream") or "unknown", "smtp_command": row.get("smtp.command_line") or row.get("smtp.req.command"),
                       "smtp_response": row.get("smtp.response"),
                       "imap_command": row.get("imap.request.command"), "imap_status": row.get("imap.response.status"),
                       "pop_command": row.get("pop.request.command"), "pop_response": row.get("pop.response.indicator") or row.get("pop.response"),
                       "certificate_der": row.get("tls.handshake.certificate"),
                       "src_port": row.get("tcp.srcport"), "dst_port": row.get("tcp.dstport"),
                       "tls_version": row.get("tls.handshake.extensions.supported_version") or row.get("tls.handshake.version") or row.get("tls.record.version"),
                       "cipher": row.get("tls.handshake.ciphersuite")})
    return events


def _first(layers: dict[str, Any], key: str) -> Any:
    value = layers.get(key)
    if isinstance(value, list): return value[0] if value else None
    if isinstance(value, dict):
        value = value.get(key) or next(iter(value.values()), None)
        if isinstance(value, list): return value[0] if value else None
    return value
