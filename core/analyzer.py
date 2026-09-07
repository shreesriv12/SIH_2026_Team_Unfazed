from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import tempfile
from cryptography import x509
from pathlib import Path

from core.models import AnalysisResult, Evidence, Session
from core.tshark import extract_email_tls_events, get_tshark_version
from protocols.imap import reconstruct as reconstruct_imap
from protocols.pop3 import reconstruct as reconstruct_pop3
from protocols.smtp import reconstruct as reconstruct_smtp
from crypto.rules import evaluate as evaluate_crypto_rules
from core.zeek import engine as zeek_engine, run_zeek
from intelligence.anomaly import score_sessions

TLS_VERSION_NAMES = {"0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2", "0x0304": "TLS 1.3"}


def analyze_pcap(pcap_path: Path) -> AnalysisResult:
    events = extract_email_tls_events(pcap_path)
    grouped: dict[str, list[dict]] = defaultdict(list)
    for event in events: grouped[event["stream"]].append(event)
    sessions, findings = [], []
    for stream, items in grouped.items():
        protocols = {item["protocol"] for item in items}
        direct = next((p for p in ("SMTP", "IMAP", "POP3") if p in protocols), None)
        ports = {str(i.get("src_port") or "") for i in items} | {str(i.get("dst_port") or "") for i in items}
        implicit_tls_ports = {"465": "SMTP", "993": "IMAP", "995": "POP3"}
        protocol = direct or next((name for port, name in implicit_tls_ports.items() if port in ports), "UNCLASSIFIED_TLS")
        classification_basis = "DIRECT" if direct else "INFERRED_PORT" if protocol != "UNCLASSIFIED_TLS" else "INSUFFICIENT_EVIDENCE"
        has_tls = any(item["protocol"] == "TLS" or item["tls_version"] for item in items)
        transition = {"SMTP": reconstruct_smtp, "IMAP": reconstruct_imap, "POP3": reconstruct_pop3}.get(protocol, lambda _, tls: "TLS_OBSERVED" if tls else "PLAINTEXT_OBSERVED")(items, has_tls)
        version = next((str(i["tls_version"]) for i in items if i["tls_version"] and "," not in str(i["tls_version"])), "NOT_OBSERVABLE")
        cipher = next((str(i["cipher"]) for i in items if i["cipher"] and "," not in str(i["cipher"])), "NOT_OBSERVABLE")
        version = TLS_VERSION_NAMES.get(version.lower(), version)
        certificate_der = next((str(i["certificate_der"]) for i in items if i.get("certificate_der")), "")
        not_after = ""
        certificate_status = "CERTIFICATE_NOT_OBSERVABLE"
        if certificate_der:
            certificate_status = "OBSERVED_UNPARSEABLE"
            try:
                der = bytes.fromhex(certificate_der.split(",")[0].replace(":", ""))
                expiry = x509.load_der_x509_certificate(der).not_valid_after_utc
                certificate_status = "EXPIRED" if expiry < datetime.now(timezone.utc) else "VALID_TIME_WINDOW"
                not_after = expiry.isoformat()
            except (ValueError, TypeError): pass
        evidence = [Evidence("tshark", "frame", i["frame"], i["frame"]) for i in items]
        evidence.extend(Evidence("tshark", "tcp.port", port, confidence="DIRECT") for port in sorted(p for p in ports if p))
        session = Session(session_id=f"tshark-stream-{stream}", protocol=protocol, transition=transition, tls_detected=has_tls,
                          tls_version=version, cipher=cipher, classification_basis=classification_basis,
                          certificate_status=certificate_status, certificate_not_after=not_after, evidence=evidence)
        sessions.append(session)
        if protocol == "SMTP" and transition == "PLAINTEXT_OBSERVED":
            findings.append({"session": session.session_id, "severity": "HIGH", "rule": "V0-STARTTLS-OBSERVATION", "title": "SMTP plaintext observed", "evidence": "TShark detected SMTP but no STARTTLS/TLS evidence in this stream. Remediation: enable and enforce STARTTLS for SMTP submission."})
        if transition in ("STARTTLS_REJECTED", "STARTTLS_ACCEPTED_NO_TLS", "STLS_REJECTED", "STLS_ACCEPTED_NO_TLS"):
            findings.append({"session": session.session_id, "severity": "HIGH", "rule": "V02-UPGRADE-FAILED", "title": "Encryption upgrade did not complete", "evidence": f"Observed {transition}. Remediation: investigate the mail server TLS configuration and enforce a successful upgrade."})
        for finding in evaluate_crypto_rules(version, certificate_status):
            finding["session"] = session.session_id
            findings.append(finding)
    zeek_counts: dict[str, int] = {}
    if zeek_engine():
        try:
            with tempfile.TemporaryDirectory(prefix="securemailscope-zeek-") as temp:
                logs = run_zeek(pcap_path, Path(temp))
            zeek_counts = {name: len(records) for name, records in logs.items()}
            for session in sessions:
                ports = {e.value for e in session.evidence if e.field == "tcp.port"}
                for ssl_log in logs.get("ssl", []):
                    if {str(ssl_log.get("id.orig_p")), str(ssl_log.get("id.resp_p"))}.isdisjoint(ports): continue
                    session.evidence.extend([Evidence("zeek", "ssl.version", str(ssl_log.get("version", "")), confidence="CORROBORATED"), Evidence("zeek", "ssl.cipher", str(ssl_log.get("cipher", "")), confidence="CORROBORATED")])
        except RuntimeError:
            pass
    severity_weight = {"CRITICAL": 80, "HIGH": 50, "MEDIUM": 25, "LOW": 10}
    for session in sessions:
        session.risk_score = min(100, sum(severity_weight.get(f["severity"], 0) for f in findings if f["session"] == session.session_id))
        session.confidence = "HIGH" if any(e.source == "zeek" and e.confidence == "CORROBORATED" for e in session.evidence) else "MEDIUM"
    score_sessions(sessions)
    return AnalysisResult(sessions, len(events), get_tshark_version(), findings, zeek_counts)
