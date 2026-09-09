from core.analyzer import assess_key_exchange

def test_forward_secrecy_assessment():
    assert assess_key_exchange("TLS 1.3", "0x1302")[1] == "SUPPORTED"
    assert assess_key_exchange("TLS 1.2", "0xc030") == ("ECDHE", "SUPPORTED")
    assert assess_key_exchange("TLS 1.2", "0x002f")[1] == "NOT_SUPPORTED"
