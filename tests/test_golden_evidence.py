import json
from pathlib import Path
from core.analyzer import engine_conflicts
from crypto.rules import evaluate

CASES = json.loads(Path("benchmarks/golden-evidence.json").read_text(encoding="utf-8"))

def test_golden_engine_conflicts():
    for item in CASES["engine_conflicts"]:
        assert engine_conflicts(item["tshark_version"], item["tshark_cipher"], item["zeek_version"], item["zeek_cipher"]) == item["expected"]

def test_golden_uncommon_crypto_cases():
    for item in CASES["crypto_cases"]:
        rules = {finding["rule"] for finding in evaluate(item["tls_version"], "VALID", cipher=item["cipher"], key_exchange=item["key_exchange"], key_share_group=item.get("key_share_group", ""))}
        assert set(item["expected_rules"]) <= rules
