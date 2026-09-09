from __future__ import annotations
from sklearn.ensemble import IsolationForest
from statistics import median

VERSIONS = {"TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}
TRANSITIONS = {"PLAINTEXT_OBSERVED": 0, "STARTTLS_REJECTED": 1, "STARTTLS_ACCEPTED_NO_TLS": 1, "STLS_REJECTED": 1, "STLS_ACCEPTED_NO_TLS": 1, "STARTTLS_TO_TLS": 2, "STLS_TO_TLS": 2, "TLS_OBSERVED": 2, "IMPLICIT_TLS": 2}

def features(session) -> list[float]:
    value = session if isinstance(session, dict) else vars(session)
    return [VERSIONS.get(value.get("tls_version"), 0), TRANSITIONS.get(value.get("transition"), 0), value.get("risk_score", 0), 1 if value.get("certificate_status") == "EXPIRED" else 0]

def score_sessions(sessions: list, baseline: list | None = None) -> None:
    """Score against persisted historical sessions, never only the current upload."""
    if not sessions:
        return
    baseline = baseline or []
    if len(baseline) < 8:
        for session in sessions:
            session.anomaly_status = "BASELINE_INSUFFICIENT"
            session.anomaly_score = None
            session.anomaly_explanation = ["At least 8 persisted historical sessions are required for a baseline."]
        return
    model = IsolationForest(contamination=0.20, random_state=42, n_estimators=100)
    model.fit([features(item) for item in baseline])
    baseline_features = [features(item) for item in baseline]
    typical_tls, typical_transition, typical_risk, typical_expired = [median(column) for column in zip(*baseline_features)]
    current = [features(item) for item in sessions]
    raw = -model.score_samples(current)
    for session, value, flag in zip(sessions, raw, model.predict(current)):
        session.anomaly_score = round(float(value) * 100, 1)
        session.anomaly_status = "ANOMALOUS" if flag == -1 else "WITHIN_BASELINE"
        current_features = features(session)
        reasons = []
        if current_features[0] < typical_tls: reasons.append("Older TLS version than the historical baseline")
        if current_features[1] < typical_transition: reasons.append("Weaker encryption transition than the historical baseline")
        if current_features[2] > typical_risk: reasons.append("Higher deterministic risk score than the historical baseline")
        if current_features[3] > typical_expired: reasons.append("Expired certificate differs from the historical baseline")
        session.anomaly_explanation = reasons if reasons else ["Feature values are within the historical baseline range."]
