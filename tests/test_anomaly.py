from types import SimpleNamespace
from intelligence.anomaly import score_sessions

def test_small_set_is_not_scored_as_ml_anomaly():
    sessions = [SimpleNamespace() for _ in range(2)]
    score_sessions(sessions)
    assert all(s.anomaly_status == "BASELINE_INSUFFICIENT" for s in sessions)

def test_historical_baseline_enables_scoring_for_a_single_new_session():
    baseline = [{"tls_version": "TLS 1.3", "transition": "STARTTLS_TO_TLS", "risk_score": 0, "certificate_status": "VALID"} for _ in range(8)]
    session = SimpleNamespace(tls_version="TLS 1.0", transition="STARTTLS_TO_TLS", risk_score=80, certificate_status="VALID")
    score_sessions([session], baseline)
    assert session.anomaly_status in {"ANOMALOUS", "WITHIN_BASELINE"}
    assert session.anomaly_score is not None
