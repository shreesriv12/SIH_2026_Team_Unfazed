from typing import Iterable

def reconstruct(events: Iterable[dict], tls_detected: bool) -> str:
    sequence = list(events)
    commands = "\n".join(str(e.get("pop_command") or "").upper() for e in sequence)
    request_index = next((index for index, event in enumerate(sequence) if "STLS" in str(event.get("pop_command") or "").upper()), None)
    requested = request_index is not None
    post_request_responses = "\n".join(str(event.get("pop_response") or "").upper() for event in sequence[(request_index + 1 if request_index is not None else len(sequence)):])
    accepted = requested and "+OK" in post_request_responses
    if requested and accepted and tls_detected: return "STLS_TO_TLS"
    if requested and accepted: return "STLS_ACCEPTED_NO_TLS"
    if requested: return "STLS_REJECTED"
    return "TLS_OBSERVED" if tls_detected else "PLAINTEXT_OBSERVED"
