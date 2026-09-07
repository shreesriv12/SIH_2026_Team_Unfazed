from __future__ import annotations
from sklearn.ensemble import IsolationForest

def score_sessions(sessions: list) -> None:
    """Attach an explainable anomaly score only when a real local baseline exists."""
    if len(sessions) < 8:
        for session in sessions:
            session.anomaly_status = "BASELINE_INSUFFICIENT"
            session.anomaly_score = None
        return
    versions = {"TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}
    transitions = {"PLAINTEXT_OBSERVED": 0, "STARTTLS_REJECTED": 1, "STARTTLS_ACCEPTED_NO_TLS": 1, "STLS_REJECTED": 1, "STLS_ACCEPTED_NO_TLS": 1, "STARTTLS_TO_TLS": 2, "STLS_TO_TLS": 2, "TLS_OBSERVED": 2}
    features = [[versions.get(s.tls_version, 0), transitions.get(s.transition, 0), s.risk_score, 1 if s.certificate_status == "EXPIRED" else 0] for s in sessions]
    # Conservative initial threshold: flag only the strongest 20% of outliers.
    model = IsolationForest(contamination=0.20, random_state=42, n_estimators=100)
    model.fit(features)
    raw = -model.score_samples(features)
    for session, value, flag in zip(sessions, raw, model.predict(features)):
        session.anomaly_score = round(float(value) * 100, 1)
        session.anomaly_status = "ANOMALOUS" if flag == -1 else "WITHIN_BASELINE"
