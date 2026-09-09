from core.tshark import implicit_tls_protocol


def test_implicit_tls_ports_are_classified_using_rfc_8314_ports():
    assert implicit_tls_protocol({"50000", "465"}) == "SMTP"
    assert implicit_tls_protocol({"993", "60123"}) == "IMAP"
    assert implicit_tls_protocol({"995", "60124"}) == "POP3"
    assert implicit_tls_protocol({"2525", "60000"}) is None
