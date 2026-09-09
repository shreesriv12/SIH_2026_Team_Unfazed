from pathlib import Path
import pytest
from core.analyzer import analyze_pcap

@pytest.mark.skipif(not Path("pcaps/smtp_tls12_expired_cert_retry.pcapng").exists(), reason="local PCAP fixture is not present")
def test_tls12_certificate_metadata_is_extracted():
    session = analyze_pcap(Path("pcaps/smtp_tls12_expired_cert_retry.pcapng")).sessions[0]
    assert session.certificate_status == "EXPIRED"
    assert session.certificate["subject"]
    assert session.certificate["public_key_size"] == "2048"
