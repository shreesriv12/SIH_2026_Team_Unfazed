from pathlib import Path
import pytest
from core.analyzer import analyze_pcap

@pytest.mark.skipif(not Path("pcaps/smtp_plain.pcapng").exists(), reason="local PCAP fixture is not present")
def test_plain_smtp_has_risk():
    result = analyze_pcap(Path("pcaps/smtp_plain.pcapng"))
    assert result.sessions[0].risk_score == 50
