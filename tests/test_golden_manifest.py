import json
from pathlib import Path

def test_golden_manifest_covers_secure_and_insecure_mail_scenarios():
    captures = json.loads(Path("benchmarks/golden-pcaps.json").read_text())["captures"]
    assert len(captures) >= 12
    assert any(not item["expected_rules"] for item in captures)
    assert {"V0-STARTTLS-OBSERVATION", "TLS-DEPRECATED-001", "X509-EXPIRED-001"} <= {rule for item in captures for rule in item["expected_rules"]}
