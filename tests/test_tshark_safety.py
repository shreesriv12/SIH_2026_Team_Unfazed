import subprocess

import pytest

from core.tshark import CaptureParseError, REASSEMBLY_OPTIONS, _execute


def test_reassembly_preferences_are_explicit():
    assert "ip.defragment:TRUE" in REASSEMBLY_OPTIONS
    assert "ipv6.defragment:TRUE" in REASSEMBLY_OPTIONS
    assert "tcp.desegment_tcp_streams:TRUE" in REASSEMBLY_OPTIONS
    assert "smtp.desegment_lines:TRUE" in REASSEMBLY_OPTIONS
    assert "pop.desegment_data:TRUE" in REASSEMBLY_OPTIONS


def test_truncated_capture_is_rejected(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "", "The file appears to have been cut short"))
    with pytest.raises(CaptureParseError, match="PCAP_TRUNCATED"):
        _execute(["tshark", "-r", "broken.pcap"])


def test_parser_timeout_has_stable_error_code(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 120)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(CaptureParseError, match="PCAP_ANALYSIS_TIMEOUT"):
        _execute(["tshark", "-r", "slow.pcap"])


def test_parser_diagnostic_is_bounded(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 2, "", "bad file format " + "x" * 1000))
    with pytest.raises(CaptureParseError) as raised:
        _execute(["tshark", "-r", "bad.pcap"])
    assert len(str(raised.value)) <= 520
