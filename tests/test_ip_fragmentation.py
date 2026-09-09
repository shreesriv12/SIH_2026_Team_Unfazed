from pathlib import Path

import pytest

from core.analyzer import analyze_pcap
from core.tshark import CaptureParseError, extract_email_tls_events


def test_complete_ipv4_fragments_are_reassembled_with_evidence():
    result = analyze_pcap(Path("pcaps/smtp_ipv4_fragmented.pcap"))
    assert len(result.sessions) == 1
    assert result.sessions[0].protocol == "SMTP"
    fragment_evidence = [item for item in result.sessions[0].evidence if item.field == "ip.fragment"]
    assert len(fragment_evidence) == 6


def test_incomplete_ipv4_fragment_set_is_rejected():
    with pytest.raises(CaptureParseError, match="PCAP_FRAGMENT_INCOMPLETE"):
        extract_email_tls_events(Path("pcaps/smtp_ipv4_fragment_incomplete.pcap"))


def test_complete_ipv6_fragments_are_reassembled():
    events = extract_email_tls_events(Path("pcaps/smtp_ipv6_fragmented.pcap"))
    assert len(events) == 4
    assert {event["stream"] for event in events} == {"0"}


def test_hostile_truncated_capture_is_rejected():
    with pytest.raises(CaptureParseError, match="PCAP_MALFORMED_PACKET"):
        extract_email_tls_events(Path("pcaps/hostile_truncated.pcapng"))
