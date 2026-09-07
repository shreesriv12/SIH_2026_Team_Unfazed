from __future__ import annotations
import json
from pathlib import Path
from typing import Any

RULEPACK = Path(__file__).resolve().parents[1] / "rules" / "crypto-v1.json"

def load_rules() -> list[dict[str, Any]]:
    return json.loads(RULEPACK.read_text(encoding="utf-8"))["rules"]

def evaluate(tls_version: str, certificate_status: str) -> list[dict[str, str]]:
    findings = []
    for rule in load_rules():
        matches = (rule["when"] == "deprecated_tls" and tls_version in rule["values"]) or (rule["when"] == "expired_certificate" and certificate_status == "EXPIRED")
        if matches: findings.append({"severity": rule["severity"], "rule": rule["id"], "title": rule["title"], "evidence": rule["remediation"]})
    return findings
