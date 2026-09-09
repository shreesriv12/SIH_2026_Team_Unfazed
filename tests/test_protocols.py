from protocols.imap import reconstruct as imap
from protocols.pop3 import reconstruct as pop3
from protocols.smtp import reconstruct as smtp

def test_smtp_states():
    assert smtp([{"smtp_command": "STARTTLS"}, {"smtp_response": "220 Ready"}], True) == "STARTTLS_TO_TLS"
    assert smtp([{"smtp_command": "STARTTLS"}, {"smtp_response": "454 unavailable"}], False) == "STARTTLS_REJECTED"
    assert smtp([{"smtp_command": "STARTTLS"}, {"smtp_response": "220 Ready"}], False) == "STARTTLS_ACCEPTED_NO_TLS"
    assert smtp([{"smtp_response": "250-STARTTLS"}], False) == "STARTTLS_ADVERTISED_IGNORED"

def test_imap_pop3_states():
    assert imap([{"imap_command": "STARTTLS", "imap_status": "OK"}], True) == "STARTTLS_TO_TLS"
    assert imap([{"imap_command": "STARTTLS", "imap_status": "OK"}], False) == "STARTTLS_ACCEPTED_NO_TLS"
    assert pop3([{"pop_command": "STLS"}, {"pop_response": "+OK"}], True) == "STLS_TO_TLS"
    assert pop3([{"pop_command": "STLS"}, {"pop_response": "+OK"}], False) == "STLS_ACCEPTED_NO_TLS"
