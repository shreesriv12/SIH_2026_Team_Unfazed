from typing import Iterable

def reconstruct(events: Iterable[dict], tls_detected: bool) -> str:
    commands = "\n".join(str(e.get("imap_command") or "").upper() for e in events)
    statuses = "\n".join(str(e.get("imap_status") or "").upper() for e in events)
    requested = "STARTTLS" in commands
    accepted = requested and "OK" in statuses
    if requested and accepted and tls_detected: return "STARTTLS_TO_TLS"
    if requested and accepted: return "STARTTLS_ACCEPTED_NO_TLS"
    if requested: return "STARTTLS_REJECTED"
    return "TLS_OBSERVED" if tls_detected else "PLAINTEXT_OBSERVED"
