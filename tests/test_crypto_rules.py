from crypto.rules import evaluate

def test_deprecated_tls_rule():
    assert evaluate("TLS 1.0", "CERTIFICATE_NOT_OBSERVABLE")[0]["rule"] == "TLS-DEPRECATED-001"

def test_expired_certificate_rule():
    assert evaluate("TLS 1.2", "EXPIRED")[0]["rule"] == "X509-EXPIRED-001"

def test_weak_cipher_and_static_rsa_include_policy_metadata():
    findings = evaluate("TLS 1.2", "VALID", cipher="0x002f", key_exchange="STATIC_RSA")
    assert {finding["rule"] for finding in findings} == {"TLS-WEAK-CIPHER-001", "TLS-STATIC-RSA-001"}
    assert all(finding["source"] and finding["rationale"] and finding["rulepack_version"] == "2026.1" for finding in findings)

def test_hostname_mismatch_and_weak_group_generate_findings():
    findings = evaluate("TLS 1.2", "VALID", {"hostname_status": "MISMATCH"}, key_share_group="1")
    assert {finding["rule"] for finding in findings} >= {"X509-HOSTNAME-MISMATCH-001", "TLS-WEAK-GROUP-001"}
