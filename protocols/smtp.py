from typing import Iterable

def reconstruct(events: Iterable[dict], tls_detected: bool) -> str:
    sequence = list(events)
    commands = "\n".join(str(e.get("smtp_command") or "").upper() for e in sequence)
    responses = "\n".join(str(e.get("smtp_response") or "") for e in sequence)
    request_index = next((index for index, event in enumerate(sequence) if "STARTTLS" in str(event.get("smtp_command") or "").upper()), None)
    requested = request_index is not None
    advertised = "STARTTLS" in responses
    post_request_responses = "\n".join(str(event.get("smtp_response") or "") for event in sequence[(request_index + 1 if request_index is not None else len(sequence)):])
    accepted = requested and "220" in post_request_responses
    if requested and accepted and tls_detected: return "STARTTLS_TO_TLS"
    if requested and accepted: return "STARTTLS_ACCEPTED_NO_TLS"
    if requested: return "STARTTLS_REJECTED"
    if advertised: return "STARTTLS_ADVERTISED_IGNORED"
    return "TLS_OBSERVED" if tls_detected else "PLAINTEXT_OBSERVED"
