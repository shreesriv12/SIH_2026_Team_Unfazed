from __future__ import annotations

import json
import csv
import io
import shutil
import subprocess
import re
from pathlib import Path
from typing import Any

DEFAULT_WINDOWS_TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
# Keep this list limited to preferences available across supported TShark builds.
# IMAP is reassembled by the TCP dissector; Wireshark 4.6 removed the older
# ``imap.desegment_body`` preference and rejects the entire command if supplied.
REASSEMBLY_OPTIONS = ["-o", "ip.defragment:TRUE", "-o", "ipv6.defragment:TRUE", "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "smtp.desegment_lines:TRUE", "-o", "pop.desegment_data:TRUE"]
CORRUPTION_MARKERS = ("cut short", "truncated", "appears to be damaged", "bad file format", "invalid packet")


class CaptureParseError(RuntimeError):
    def __init__(self, code: str, detail: str):
        self.code = code
        clean = " ".join(detail.replace("\x00", "").split())[:500]
        super().__init__(f"{code}: {clean}")


def _execute(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=120)
    except subprocess.TimeoutExpired as error:
        raise CaptureParseError("PCAP_ANALYSIS_TIMEOUT", "TShark exceeded the 120 second safety limit.") from error
    diagnostic = completed.stderr.strip()
    if completed.returncode != 0:
        raise CaptureParseError("PCAP_MALFORMED", diagnostic or f"TShark exited with status {completed.returncode}.")
    if diagnostic and any(marker in diagnostic.lower() for marker in CORRUPTION_MARKERS):
        raise CaptureParseError("PCAP_TRUNCATED", diagnostic)
    return completed


def classify_protocol(protocols: str, payload_hex: str) -> tuple[str, str]:
    """Identify email traffic when a service runs on a non-standard TCP port."""
    lowered = protocols.lower()
    if "smtp" in lowered: return "SMTP", "DIRECT"
    if "imap" in lowered: return "IMAP", "DIRECT"
    if "pop" in lowered: return "POP3", "DIRECT"
    try:
        payload = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", payload_hex)).decode("utf-8", errors="ignore").upper()
    except ValueError: payload = ""
    if "STLS" in payload or payload.startswith("+OK") and "POP3" in payload: return "POP3", "HEURISTIC_PAYLOAD"
    if re.search(r"(?:^|\r?\n)[A-Z0-9]+\s+STARTTLS\b", payload) or "* OK" in payload and "IMAP" in payload: return "IMAP", "HEURISTIC_PAYLOAD"
    if any(marker in payload for marker in ("EHLO ", "HELO ", "MAIL FROM:", "250-STARTTLS", "220 ")): return "SMTP", "HEURISTIC_PAYLOAD"
    return "TLS_UNCLASSIFIED", "INSUFFICIENT_EVIDENCE"


def classify_stream(events: list[dict[str, Any]]) -> tuple[str | None, str]:
    """Classify a complete TCP dialogue without relying on service ports."""
    direct = {event.get("protocol") for event in events} & {"SMTP", "IMAP", "POP3"}
    if direct: return next(p for p in ("SMTP", "IMAP", "POP3") if p in direct), "DIRECT"
    payload = ""
    for event in events:
        try: payload += bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", str(event.get("payload_hex", "")))).decode("utf-8", errors="ignore")
        except ValueError: continue
    upper = payload.upper()
    patterns = {
        "SMTP": (r"^220[- ].*(?:SMTP|ESMTP)", r"^(?:EHLO|HELO)\s+", r"^MAIL FROM:", r"^RCPT TO:", r"^250[- ].*STARTTLS", r"^STARTTLS\s*$"),
        "IMAP": (r"^\* OK .*IMAP", r"^[A-Z0-9]+\s+(?:CAPABILITY|LOGIN|SELECT|STARTTLS|LOGOUT)\b", r"^\* (?:CAPABILITY|BYE|FLAGS)\b", r"^[A-Z0-9]+\s+(?:OK|NO|BAD)\b"),
        "POP3": (r"^\+OK.*POP", r"^(?:USER|PASS|STAT|LIST|RETR|DELE|CAPA|STLS|QUIT)(?:\s|$)", r"^-ERR(?:\s|$)"),
    }
    scores = {name: sum(bool(re.search(pattern, upper, re.MULTILINE)) for pattern in signatures) for name, signatures in patterns.items()}
    winner = max(scores, key=scores.get); ordered = sorted(scores.values(), reverse=True)
    if scores[winner] >= 2 and ordered[0] > ordered[1]: return winner, "REASSEMBLED_STREAM_SIGNATURE"
    return None, "INSUFFICIENT_EVIDENCE"


def implicit_tls_protocol(ports: set[str]) -> str | None:
    """Well-known implicit-TLS email service ports (RFC 8314)."""
    mapping = {"465": "SMTP", "993": "IMAP", "995": "POP3"}
    return next((protocol for port, protocol in mapping.items() if port in ports), None)


def get_tshark_path() -> str:
    installed = shutil.which("tshark")
    if installed:
        return installed
    if DEFAULT_WINDOWS_TSHARK.exists():
        return str(DEFAULT_WINDOWS_TSHARK)
    return _missing()


def _missing() -> str:
    raise FileNotFoundError("TShark was not found in PATH or C:\\Program Files\\Wireshark\\tshark.exe")


def get_tshark_version() -> str:
    completed = subprocess.run([get_tshark_path(), "--version"], capture_output=True, text=True, check=True)
    return completed.stdout.splitlines()[0].strip()


def run_tshark_json(pcap_path: Path) -> list[dict[str, Any]]:
    pcap_path = pcap_path.resolve()
    if not pcap_path.is_file(): raise FileNotFoundError(pcap_path)
    command = [get_tshark_path(), "-r", str(pcap_path), *REASSEMBLY_OPTIONS, "-d", "tcp.port==2525,smtp", "-d", "tcp.port==2526,smtp", "-d", "tcp.port==2527,smtp", "-d", "tcp.port==2528,smtp", "-d", "tcp.port==2529,smtp", "-d", "tcp.port==2530,smtp", "-d", "tcp.port==2143,imap", "-d", "tcp.port==2144,imap", "-d", "tcp.port==2110,pop", "-d", "tcp.port==2111,pop", "-Y", "smtp || imap || pop || tls", "-T", "json"]
    completed = _execute(command)
    try: return json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as error: raise CaptureParseError("TSHARK_OUTPUT_INVALID", "TShark returned invalid JSON.") from error


def extract_email_tls_events(pcap_path: Path) -> list[dict[str, Any]]:
    """Extract a small, stable evidence table rather than depending on dissector-tree JSON."""
    malformed = _execute([get_tshark_path(), "-r", str(pcap_path.resolve()), "-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number"])
    if malformed.stdout.strip():
        frames = ",".join(malformed.stdout.splitlines()[:10])
        raise CaptureParseError("PCAP_MALFORMED_PACKET", f"TShark marked malformed frame(s): {frames}.")
    fields = ["frame.number", "frame.time_epoch", "tcp.stream", "tcp.srcport", "tcp.dstport", "frame.protocols", "smtp.req.command", "smtp.command_line", "smtp.response", "imap.request.command", "imap.response.status", "pop.request.command", "pop.response", "pop.response.indicator", "tls.handshake.certificate",
              "tls.record.version", "tls.handshake.version", "tls.handshake.extensions.supported_version", "tls.handshake.ciphersuite", "tls.handshake.extensions_server_name", "tls.handshake.extensions_key_share_group", "tls.handshake.extensions_supported_group", "tcp.payload"]
    fragment_fields = ["ip.src", "ip.dst", "ip.id", "ip.flags.mf", "ip.frag_offset", "ip.fragment", "ip.fragment.overlap", "ip.fragment.overlap.conflict", "ip.fragment.multipletails", "ip.fragment.toolongfragment", "ip.fragment.error", "ip.reassembled_in", "ip.reassembled.length", "ipv6.src", "ipv6.dst", "ipv6.fraghdr.ident", "ipv6.fraghdr.offset", "ipv6.fraghdr.more", "ipv6.fragment", "ipv6.fragment.overlap", "ipv6.fragment.overlap.conflict", "ipv6.fragment.multipletails", "ipv6.fragment.toolongfragment", "ipv6.fragment.error", "ipv6.reassembled.in", "ipv6.reassembled.length"]
    fields.extend(fragment_fields)
    command = [get_tshark_path(), "-r", str(pcap_path.resolve()), *REASSEMBLY_OPTIONS, "-d", "tcp.port==2525,smtp", "-d", "tcp.port==2526,smtp", "-d", "tcp.port==2527,smtp", "-d", "tcp.port==2528,smtp", "-d", "tcp.port==2529,smtp", "-d", "tcp.port==2530,smtp", "-d", "tcp.port==2143,imap", "-d", "tcp.port==2144,imap", "-d", "tcp.port==2145,imap", "-d", "tcp.port==2110,pop", "-d", "tcp.port==2111,pop", "-d", "tcp.port==2112,pop", "-Y", "tcp || ip.flags.mf || ip.frag_offset > 0 || ipv6.fraghdr",
               "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d"]
    for field in fields: command.extend(["-e", field])
    completed = _execute(command)
    events = []
    for row in csv.DictReader(io.StringIO(completed.stdout), delimiter="\t"):
        protocols = row.get("frame.protocols", "")
        protocol, protocol_basis = classify_protocol(protocols, row.get("tcp.payload", ""))
        issues = [field for field in fragment_fields if any(token in field for token in ("overlap", "multipletails", "toolongfragment", "fragment.error")) and row.get(field) not in (None, "", "0", "False", "false")]
        events.append({"frame": row.get("frame.number") or "?", "protocol": protocol,
                       "protocol_basis": protocol_basis,
                       "timestamp": row.get("frame.time_epoch"),
                       "stream": row.get("tcp.stream") or "unknown", "smtp_command": row.get("smtp.command_line") or row.get("smtp.req.command"),
                       "smtp_response": row.get("smtp.response"),
                       "imap_command": row.get("imap.request.command"), "imap_status": row.get("imap.response.status"),
                       "pop_command": row.get("pop.request.command"), "pop_response": row.get("pop.response.indicator") or row.get("pop.response"),
                       "certificate_der": row.get("tls.handshake.certificate"),
                       "src_port": row.get("tcp.srcport"), "dst_port": row.get("tcp.dstport"),
                       "tls_version": row.get("tls.handshake.extensions.supported_version") or row.get("tls.handshake.version") or row.get("tls.record.version"),
                       "cipher": row.get("tls.handshake.ciphersuite"), "sni": row.get("tls.handshake.extensions_server_name"), "key_share_group": row.get("tls.handshake.extensions_key_share_group"), "supported_groups": row.get("tls.handshake.extensions_supported_group"), "payload_hex": row.get("tcp.payload", ""),
                       "fragmented": bool(row.get("ip.fragment") or row.get("ipv6.fragment") or row.get("ip.flags.mf") in {"1", "True", "true"} or row.get("ip.frag_offset") not in {None, "", "0"} or row.get("ipv6.fraghdr.more") in {"1", "True", "true"} or row.get("ipv6.fraghdr.offset") not in {None, "", "0"}),
                       "fragment_key": "|".join((row.get("ip.src") or row.get("ipv6.src") or "", row.get("ip.dst") or row.get("ipv6.dst") or "", row.get("ip.id") or row.get("ipv6.fraghdr.ident") or "")),
                       "fragment_offset": row.get("ip.frag_offset") or row.get("ipv6.fraghdr.offset"),
                       "reassembled_in": row.get("ip.reassembled_in") or row.get("ipv6.reassembled.in"),
                       "reassembled_length": row.get("ip.reassembled.length") or row.get("ipv6.reassembled.length"),
                       "fragment_issues": issues})
    streams_by_frame = {event["frame"]: event["stream"] for event in events if event["stream"] != "unknown"}
    streams_by_fragment = {event["fragment_key"]: event["stream"] for event in events if event["stream"] != "unknown" and event.get("fragment_key", "||") != "||"}
    for event in events:
        if event["stream"] == "unknown" and event.get("reassembled_in") in streams_by_frame:
            event["stream"] = streams_by_frame[event["reassembled_in"]]
        if event["stream"] == "unknown" and event.get("fragment_key") in streams_by_fragment:
            event["stream"] = streams_by_fragment[event["fragment_key"]]
    incomplete = {event.get("fragment_key") for event in events if event.get("fragmented") and event.get("fragment_key", "||") != "||" and event["stream"] == "unknown"}
    if incomplete: raise CaptureParseError("PCAP_FRAGMENT_INCOMPLETE", f"{len(incomplete)} IP fragment set(s) could not be reassembled.")
    return events


def _first(layers: dict[str, Any], key: str) -> Any:
    value = layers.get(key)
    if isinstance(value, list): return value[0] if value else None
    if isinstance(value, dict):
        value = value.get(key) or next(iter(value.values()), None)
        if isinstance(value, list): return value[0] if value else None
    return value
