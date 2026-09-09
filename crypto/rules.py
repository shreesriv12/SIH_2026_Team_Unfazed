from __future__ import annotations
import json
from pathlib import Path
from typing import Any

RULEPACK = Path(__file__).resolve().parents[1] / "rules" / "crypto-v1.json"

def load_rules() -> list[dict[str, Any]]:
    return json.loads(RULEPACK.read_text(encoding="utf-8"))["rules"]

def evaluate(tls_version: str, certificate_status: str, certificate: dict[str, str] | None = None, cipher: str = "", key_exchange: str = "", key_share_group: str = "") -> list[dict[str, str]]:
    certificate = certificate or {}
    findings = []
    for rule in load_rules():
        signature = certificate.get("signature_algorithm", "").lower()
        key_size = int(certificate.get("public_key_size", "0") or 0)
        matches = (rule["when"] == "deprecated_tls" and tls_version in rule.get("values", [])) or (rule["when"] == "expired_certificate" and certificate_status == "EXPIRED") or (rule["when"] == "weak_rsa_key" and certificate.get("public_key_algorithm") == "RSAPublicKey" and 0 < key_size < 2048) or (rule["when"] == "weak_signature" and ("md5" in signature or "sha1" in signature)) or (rule["when"] == "not_yet_valid" and certificate_status == "NOT_YET_VALID") or (rule["when"] == "weak_cipher" and cipher.lower() in {value.lower() for value in rule.get("values", [])}) or (rule["when"] == "static_key_exchange" and key_exchange in rule.get("values", [])) or (rule["when"] == "hostname_mismatch" and certificate.get("hostname_status") == "MISMATCH") or (rule["when"] == "weak_key_share_group" and key_share_group in rule.get("values", []))
        if matches:
            findings.append({"severity": rule["severity"], "rule": rule["id"], "title": rule["title"], "evidence": rule["remediation"], "rationale": rule["rationale"], "source": rule["source"], "rulepack_version": json.loads(RULEPACK.read_text(encoding="utf-8"))["version"]})
    return findings
