from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Evidence:
    source: str
    field: str
    value: str
    frame: str | None = None
    confidence: str = "DIRECT"


@dataclass
class Session:
    session_id: str
    protocol: str
    transition: str
    tls_detected: bool
    tls_version: str = "NOT_OBSERVABLE"
    cipher: str = "NOT_OBSERVABLE"
    classification_basis: str = "DIRECT"
    certificate_status: str = "CERTIFICATE_NOT_OBSERVABLE"
    certificate_not_after: str = ""
    risk_score: int = 0
    confidence: str = "MEDIUM"
    anomaly_score: float | None = None
    anomaly_status: str = "BASELINE_INSUFFICIENT"
    evidence: list[Evidence] = field(default_factory=list)

    def table_row(self) -> dict[str, str]:
        return {"Session": self.session_id, "Protocol": self.protocol, "Basis": self.classification_basis, "Transition": self.transition,
                "TLS": self.tls_version, "Cipher": self.cipher, "Certificate": self.certificate_status, "Risk": str(self.risk_score), "Confidence": self.confidence, "Evidence": str(len(self.evidence))}


@dataclass
class AnalysisResult:
    sessions: list[Session]
    packet_count: int
    tshark_version: str
    findings: list[dict[str, str]]
    zeek_log_counts: dict[str, int] = field(default_factory=dict)

    @property
    def high_risk_count(self) -> int:
        return sum(f["severity"] in ("HIGH", "CRITICAL") for f in self.findings)

    @property
    def top_risk(self) -> int:
        return min(100, 35 * self.high_risk_count)

    @property
    def protocols(self) -> list[str]:
        return sorted({s.protocol for s in self.sessions})

    @property
    def session_table(self) -> list[dict[str, str]]:
        return [s.table_row() for s in self.sessions]

    def as_dict(self) -> dict[str, Any]:
        return {"packet_count": self.packet_count, "tshark_version": self.tshark_version, "zeek_log_counts": self.zeek_log_counts,
                "sessions": [asdict(s) for s in self.sessions], "findings": self.findings}
