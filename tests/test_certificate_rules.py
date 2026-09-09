from crypto.rules import evaluate

def test_weak_key_and_signature_rules():
    cert = {"public_key_algorithm":"RSAPublicKey", "public_key_size":"1024", "signature_algorithm":"sha1WithRSAEncryption"}
    rules = {finding["rule"] for finding in evaluate("TLS 1.2", "VALID", cert)}
    assert {"X509-WEAK-KEY-001", "X509-WEAK-SIGNATURE-001"} <= rules
