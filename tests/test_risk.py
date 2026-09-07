from pathlib import Path
from core.analyzer import analyze_pcap

def test_plain_smtp_has_risk():
    result = analyze_pcap(Path("pcaps/smtp_plain.pcapng"))
    assert result.sessions[0].risk_score == 50
