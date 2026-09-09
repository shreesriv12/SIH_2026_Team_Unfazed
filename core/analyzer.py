from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import tempfile
import time
import tracemalloc
import re
from functools import lru_cache
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from pathlib import Path

from core.models import AnalysisResult, Evidence, Session
from core.tshark import classify_stream, extract_email_tls_events, get_tshark_version, implicit_tls_protocol
from protocols.imap import reconstruct as reconstruct_imap
from protocols.pop3 import reconstruct as reconstruct_pop3
from protocols.smtp import reconstruct as reconstruct_smtp
from crypto.rules import evaluate as evaluate_crypto_rules
from core.zeek import engine as zeek_engine, run_zeek
from intelligence.anomaly import score_sessions
from config import settings

TLS_VERSION_NAMES = {"0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2", "0x0304": "TLS 1.3"}
CIPHER_NAMES = {"0x1301":"TLS_AES_128_GCM_SHA256","0x1302":"TLS_AES_256_GCM_SHA384","0x1303":"TLS_CHACHA20_POLY1305_SHA256","0xc014":"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","0xc030":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","0x002f":"TLS_RSA_WITH_AES_128_CBC_SHA","0x0035":"TLS_RSA_WITH_AES_256_CBC_SHA"}


def certificate_hostname_status(certificate: x509.Certificate, hostname: str) -> str:
    if not hostname: return "HOSTNAME_NOT_OBSERVABLE"
    try: names = list(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound: names = [item.value for item in certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    host = hostname.rstrip(".").lower()
    for name in names:
        candidate = name.rstrip(".").lower()
        if candidate == host: return "MATCHED"
        if candidate.startswith("*.") and host.count(".") == candidate.count(".") and host.endswith(candidate[1:]): return "MATCHED"
    return "MISMATCH"


def normalized_engine_value(field: str, value: str) -> str:
    value = value.strip()
    if field == "tls.version":
        digits = "".join(character for character in value if character.isdigit() or character == ".")
        return f"TLS{digits[0]}.{digits[1]}" if len(digits) == 2 and "." not in digits else f"TLS{digits}"
    return CIPHER_NAMES.get(value.lower(), value).upper()


def engine_conflicts(tshark_version: str, tshark_cipher: str, zeek_version: str, zeek_cipher: str) -> list[str]:
    conflicts = []
    if tshark_version and zeek_version and tshark_version != "NOT_OBSERVABLE" and normalized_engine_value("tls.version", tshark_version) != normalized_engine_value("tls.version", zeek_version): conflicts.append("TLS_VERSION")
    if tshark_cipher and zeek_cipher and tshark_cipher != "NOT_OBSERVABLE" and normalized_engine_value("tls.cipher", tshark_cipher) != normalized_engine_value("tls.cipher", zeek_cipher): conflicts.append("TLS_CIPHER")
    return conflicts

def assess_key_exchange(version: str, cipher: str) -> tuple[str, str]:
    if version == "TLS 1.3": return "EPHEMERAL_DHE_OR_ECDHE", "SUPPORTED"
    name = CIPHER_NAMES.get(cipher.lower(), cipher)
    if "ECDHE" in name: return "ECDHE", "SUPPORTED"
    if "DHE" in name: return "DHE", "SUPPORTED"
    if "_RSA_" in name: return "STATIC_RSA", "NOT_SUPPORTED"
    return "NOT_OBSERVABLE", "NOT_OBSERVABLE"


def assess_certificate_chain(certificates: list[x509.Certificate]) -> str:
    """Verify supplied certificate-to-issuer links; a PCAP cannot prove trust-store status."""
    if len(certificates) == 1: return "LEAF_ONLY_CHAIN_INCOMPLETE"
    for child, issuer in zip(certificates, certificates[1:]):
        if child.issuer != issuer.subject: return "CHAIN_LINK_SUBJECT_MISMATCH"
        key = issuer.public_key()
        try:
            if isinstance(key, rsa.RSAPublicKey): key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
            elif isinstance(key, ec.EllipticCurvePublicKey): key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
            elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)): key.verify(child.signature, child.tbs_certificate_bytes)
            else: return "CHAIN_LINK_UNSUPPORTED_KEY"
        except Exception: return "CHAIN_LINK_SIGNATURE_INVALID"
    return "CHAIN_LINKS_VERIFIED_TRUST_NOT_VALIDATED"


def _verify_certificate_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey): key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey): key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)): key.verify(child.signature, child.tbs_certificate_bytes)
        else: return False
        return True
    except Exception: return False


@lru_cache(maxsize=4)
def load_trust_roots(bundle_path: str) -> tuple[x509.Certificate, ...]:
    if not bundle_path: return ()
    try: content = Path(bundle_path).read_bytes()
    except OSError: return ()
    blocks = re.findall(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", content, re.DOTALL)
    roots = []
    for block in blocks:
        try: roots.append(x509.load_pem_x509_certificate(block))
        except ValueError: continue
    return tuple(roots)


def assess_certificate_trust(chain: list[x509.Certificate], trust_roots: list[x509.Certificate] | tuple[x509.Certificate, ...], at_time: datetime | None = None) -> str:
    if not chain: return "CERTIFICATE_NOT_OBSERVABLE"
    if not trust_roots: return "TRUST_STORE_NOT_CONFIGURED"
    moment = at_time or datetime.now(timezone.utc)
    roots = {cert.fingerprint(hashes.SHA256()): cert for cert in trust_roots}
    candidates = list(chain[1:]) + list(trust_roots)
    current, seen = chain[0], set()
    for _ in range(12):
        fingerprint = current.fingerprint(hashes.SHA256())
        if fingerprint in seen: return "CHAIN_LOOP"
        seen.add(fingerprint)
        if moment < current.not_valid_before_utc or moment > current.not_valid_after_utc: return "CHAIN_CERTIFICATE_TIME_INVALID"
        if fingerprint in roots: return "TRUSTED"
        issuer = next((cert for cert in candidates if cert.subject == current.issuer and cert.fingerprint(hashes.SHA256()) not in seen), None)
        if issuer is None: return "UNTRUSTED_ROOT" if current.subject == current.issuer else "INCOMPLETE_CHAIN"
        if not _verify_certificate_signature(current, issuer): return "CHAIN_SIGNATURE_INVALID"
        try:
            if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca: return "CHAIN_ISSUER_NOT_CA"
        except x509.ExtensionNotFound: return "CHAIN_ISSUER_NOT_CA"
        current = issuer
    return "CHAIN_TOO_DEEP"


def analyze_pcap(pcap_path: Path, historical_baseline: list[dict] | None = None) -> AnalysisResult:
    started = time.perf_counter(); tracemalloc.start()
    events = extract_email_tls_events(pcap_path)
    grouped: dict[str, list[dict]] = defaultdict(list)
    for event in events: grouped[event["stream"]].append(event)
    sessions, findings, relevant_event_count = [], [], 0
    for stream, items in grouped.items():
        protocols = {item["protocol"] for item in items}
        direct = next((p for p in ("SMTP", "IMAP", "POP3") if p in protocols), None)
        ports = {str(i.get("src_port") or "") for i in items} | {str(i.get("dst_port") or "") for i in items}
        inferred_protocol = implicit_tls_protocol(ports)
        has_tls = any(item["protocol"] == "TLS" or item["tls_version"] for item in items)
        stream_protocol, stream_basis = classify_stream(items)
        if not (direct or stream_protocol or inferred_protocol or has_tls): continue
        relevant_event_count += sum(bool(item.get("payload_hex") or item.get("tls_version") or item.get("protocol") in {"SMTP", "IMAP", "POP3"}) for item in items)
        protocol = direct or stream_protocol or inferred_protocol or "UNCLASSIFIED_TLS"
        classification_basis = "DIRECT" if direct else stream_basis if stream_protocol else "INFERRED_PORT" if inferred_protocol else "INSUFFICIENT_EVIDENCE"
        transition = "IMPLICIT_TLS" if inferred_protocol and not direct and has_tls else {"SMTP": reconstruct_smtp, "IMAP": reconstruct_imap, "POP3": reconstruct_pop3}.get(protocol, lambda _, tls: "TLS_OBSERVED" if tls else "PLAINTEXT_OBSERVED")(items, has_tls)
        version = next((str(i["tls_version"]) for i in items if i["tls_version"] and "," not in str(i["tls_version"])), "NOT_OBSERVABLE")
        cipher = next((str(i["cipher"]) for i in items if i["cipher"] and "," not in str(i["cipher"])), "NOT_OBSERVABLE")
        sni = next((str(i["sni"]) for i in items if i.get("sni")), "")
        key_share_group = next((str(i["key_share_group"]) for i in items if i.get("key_share_group") and "," not in str(i["key_share_group"])), "NOT_OBSERVABLE")
        version = TLS_VERSION_NAMES.get(version.lower(), version)
        key_exchange, forward_secrecy = assess_key_exchange(version, cipher)
        certificate_der = next((str(i["certificate_der"]) for i in items if i.get("certificate_der")), "")
        not_after = ""
        certificate: dict[str, str] = {}
        certificate_status = "CERTIFICATE_NOT_OBSERVABLE"
        if certificate_der:
            certificate_status = "OBSERVED_UNPARSEABLE"
            try:
                chain = [x509.load_der_x509_certificate(bytes.fromhex(encoded.replace(":", ""))) for encoded in certificate_der.split(",") if encoded]
                cert = chain[0]
                expiry = cert.not_valid_after_utc
                public_key = cert.public_key()
                begins = cert.not_valid_before_utc
                certificate = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "not_before": begins.isoformat(), "not_after": expiry.isoformat(), "public_key_algorithm": type(public_key).__name__, "public_key_size": str(getattr(public_key, "key_size", "NOT_APPLICABLE")), "signature_algorithm": cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string, "chain_depth": str(len(chain)), "chain_status": assess_certificate_chain(chain), "trust_status": assess_certificate_trust(chain, load_trust_roots(settings.ca_bundle)), "sni": sni or "NOT_OBSERVABLE", "hostname_status": certificate_hostname_status(cert, sni)}
                certificate_status = "EXPIRED" if expiry < datetime.now(timezone.utc) else "NOT_YET_VALID" if begins > datetime.now(timezone.utc) else "VALID"
                not_after = expiry.isoformat()
            except (ValueError, TypeError): pass
        evidence = []
        for item in items:
            frame, timestamp = item["frame"], item.get("timestamp")
            evidence.append(Evidence("tshark", "frame.number", frame, frame=frame, timestamp=timestamp, raw_value=frame))
            for field in ("smtp_command", "smtp_response", "imap_command", "imap_status", "pop_command", "pop_response", "tls_version", "cipher", "sni", "key_share_group", "supported_groups"):
                value = str(item.get(field) or "")
                if value:
                    evidence.append(Evidence("tshark", field, value, frame=frame, timestamp=timestamp, raw_value=value))
            if item.get("fragmented"):
                evidence.append(Evidence("tshark", "ip.fragment", str(item.get("fragment_offset") or "0"), frame=frame, timestamp=timestamp, raw_value=str(item.get("fragment_offset") or "0"), derived_value=f"reassembled_in={item.get('reassembled_in') or 'NOT_OBSERVED'}"))
            if item.get("reassembled_length"):
                evidence.append(Evidence("tshark", "ip.reassembled.length", str(item["reassembled_length"]), frame=frame, timestamp=timestamp, raw_value=str(item["reassembled_length"]), derived_value="IP_PAYLOAD_REASSEMBLED"))
        evidence.extend(Evidence("tshark", "tcp.port", port, raw_value=port, derived_value=protocol) for port in sorted(p for p in ports if p))
        evidence.append(Evidence("analyzer", "protocol.classification", protocol, raw_value=",".join(sorted(protocols)), derived_value=classification_basis, confidence=classification_basis))
        if inferred_protocol:
            matched_port = next(port for port in ("465", "993", "995") if port in ports)
            evidence.append(Evidence("analyzer", "implicit_tls.port", matched_port, raw_value=matched_port, derived_value=f"{inferred_protocol} / IMPLICIT_TLS", confidence="INFERRED_PORT"))
        evidence.append(Evidence("analyzer", "transport.transition", transition, derived_value=transition))
        session = Session(session_id=f"tshark-stream-{stream}", protocol=protocol, transition=transition, tls_detected=has_tls,
                          tls_version=version, cipher=cipher, classification_basis=classification_basis,
                          certificate_status=certificate_status, certificate_not_after=not_after, certificate=certificate, evidence=evidence)
        session.key_exchange = key_exchange
        session.forward_secrecy = forward_secrecy
        sessions.append(session)
        if protocol == "SMTP" and transition == "PLAINTEXT_OBSERVED":
            findings.append({"session": session.session_id, "severity": "HIGH", "rule": "V0-STARTTLS-OBSERVATION", "title": "SMTP plaintext observed", "evidence": "TShark detected SMTP but no STARTTLS/TLS evidence in this stream. Remediation: enable and enforce STARTTLS for SMTP submission."})
        if protocol == "SMTP" and transition == "STARTTLS_ADVERTISED_IGNORED":
            findings.append({"session": session.session_id, "severity": "HIGH", "rule": "V01-STARTTLS-IGNORED", "title": "SMTP STARTTLS was advertised but not used", "evidence": "The server advertised STARTTLS but the client did not request an encryption upgrade. Remediation: configure the client to require STARTTLS and reject plaintext fallback."})
        if transition in ("STARTTLS_REJECTED", "STARTTLS_ACCEPTED_NO_TLS", "STLS_REJECTED", "STLS_ACCEPTED_NO_TLS"):
            findings.append({"session": session.session_id, "severity": "HIGH", "rule": "V02-UPGRADE-FAILED", "title": "Encryption upgrade did not complete", "evidence": f"Observed {transition}. Remediation: investigate the mail server TLS configuration and enforce a successful upgrade."})
        fragment_issues = sorted({issue for item in items for issue in item.get("fragment_issues", [])})
        if fragment_issues:
            findings.append({"session": session.session_id, "severity": "HIGH", "rule": "PCAP-FRAGMENT-ANOMALY-001", "title": "Unsafe IP fragment pattern observed", "evidence": f"TShark reported: {', '.join(fragment_issues)}. Treat reconstruction as untrusted and inspect the source capture."})
        for finding in evaluate_crypto_rules(version, certificate_status, certificate, cipher, key_exchange, key_share_group):
            finding["session"] = session.session_id
            findings.append(finding)
    zeek_counts: dict[str, int] = {}
    zeek_logs: dict[str, list[dict]] = {}
    if zeek_engine():
        try:
            with tempfile.TemporaryDirectory(prefix="securemailscope-zeek-") as temp:
                logs = run_zeek(pcap_path, Path(temp))
            zeek_logs = logs
            zeek_counts = {name: len(records) for name, records in logs.items()}
            for session in sessions:
                ports = {e.value for e in session.evidence if e.field == "tcp.port"}
                for ssl_log in logs.get("ssl", []):
                    if {str(ssl_log.get("id.orig_p")), str(ssl_log.get("id.resp_p"))}.isdisjoint(ports): continue
                    version_value, cipher_value = str(ssl_log.get("version", "")), str(ssl_log.get("cipher", ""))
                    conflicts = engine_conflicts(session.tls_version, session.cipher, version_value, cipher_value)
                    session.engine_conflicts.extend(conflict for conflict in conflicts if conflict not in session.engine_conflicts)
                    version_confidence = "CONFLICT" if "TLS_VERSION" in conflicts else "CORROBORATED"
                    cipher_confidence = "CONFLICT" if "TLS_CIPHER" in conflicts else "CORROBORATED"
                    session.evidence.extend([Evidence("zeek", "ssl.version", version_value, raw_value=version_value, derived_value=session.tls_version, confidence=version_confidence), Evidence("zeek", "ssl.cipher", cipher_value, raw_value=cipher_value, derived_value=session.cipher, confidence=cipher_confidence)])
        except RuntimeError:
            pass
    severity_weight = {"CRITICAL": 80, "HIGH": 50, "MEDIUM": 25, "LOW": 10}
    for session in sessions:
        for conflict in session.engine_conflicts:
            findings.append({"session": session.session_id, "severity": "MEDIUM", "rule": "ENGINE-CONFLICT-001", "title": "TShark and Zeek evidence conflict", "evidence": f"The engines disagree on {conflict}. Verify the PCAP, dissector configuration, and engine versions before relying on this conclusion."})
        session.risk_score = min(100, sum(severity_weight.get(f["severity"], 0) for f in findings if f["session"] == session.session_id))
        session.confidence = "LOW" if session.engine_conflicts else "HIGH" if any(e.source == "zeek" and e.confidence == "CORROBORATED" for e in session.evidence) else "MEDIUM"
    score_sessions(sessions, historical_baseline)
    _, peak_bytes = tracemalloc.get_traced_memory(); tracemalloc.stop()
    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    performance = {"analysis_time_ms": elapsed_ms, "peak_python_memory_mb": round(peak_bytes / (1024 * 1024), 2), "events_per_second": round(relevant_event_count / max(elapsed_ms / 1000, 0.001), 2)}
    return AnalysisResult(sessions, relevant_event_count, get_tshark_version(), findings, zeek_counts, zeek_logs, performance)
