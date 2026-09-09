from core.tshark import classify_protocol, classify_stream


def test_nonstandard_port_payload_fingerprints_are_classified():
    assert classify_protocol("eth:ip:tcp:data", "45484c4f20636c69656e742e6c6f63616c0d0a")[0] == "SMTP"
    assert classify_protocol("eth:ip:tcp:data", "61303031205354415254544c530d0a")[0] == "IMAP"
    assert classify_protocol("eth:ip:tcp:data", "53544c530d0a")[0] == "POP3"


def encoded(text: str) -> dict:
    return {"protocol": "TLS_UNCLASSIFIED", "payload_hex": text.encode().hex()}


def test_reassembled_dialogue_detects_smtp_across_segments():
    events = [encoded("220 mail.example ESM"), encoded("TP ready\r\nEHLO client\r\n"), encoded("MAIL FROM:<sender@example.test>\r\n")]
    assert classify_stream(events) == ("SMTP", "REASSEMBLED_STREAM_SIGNATURE")


def test_reassembled_dialogue_detects_imap_and_pop3():
    assert classify_stream([encoded("* OK IMAP4rev1 ready\r\n"), encoded("A001 CAPABILITY\r\n")])[0] == "IMAP"
    assert classify_stream([encoded("+OK POP3 ready\r\n"), encoded("USER alice\r\nSTAT\r\n")])[0] == "POP3"


def test_unrelated_tcp_dialogue_is_not_guessed():
    assert classify_stream([encoded("GET / HTTP/1.1\r\nHost: example.test\r\n")]) == (None, "INSUFFICIENT_EVIDENCE")
