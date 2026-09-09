from dataclasses import asdict

from core.models import Evidence


def test_evidence_preserves_packet_timeline_and_derivation():
    evidence = Evidence(
        "tshark", "smtp_command", "STARTTLS", frame="10", timestamp="1725790000.021450",
        raw_value="STARTTLS", derived_value="UPGRADE_REQUESTED",
    )
    exported = asdict(evidence)
    assert exported["frame"] == "10"
    assert exported["timestamp"] == "1725790000.021450"
    assert exported["raw_value"] == "STARTTLS"
    assert exported["derived_value"] == "UPGRADE_REQUESTED"
