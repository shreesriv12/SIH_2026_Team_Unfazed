from crypto.rules import evaluate

def test_deprecated_tls_rule():
    assert evaluate("TLS 1.0", "CERTIFICATE_NOT_OBSERVABLE")[0]["rule"] == "TLS-DEPRECATED-001"

def test_expired_certificate_rule():
    assert evaluate("TLS 1.2", "EXPIRED")[0]["rule"] == "X509-EXPIRED-001"
