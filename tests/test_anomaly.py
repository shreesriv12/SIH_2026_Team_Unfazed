from types import SimpleNamespace
from intelligence.anomaly import score_sessions

def test_small_set_is_not_scored_as_ml_anomaly():
    sessions = [SimpleNamespace() for _ in range(2)]
    score_sessions(sessions)
    assert all(s.anomaly_status == "BASELINE_INSUFFICIENT" for s in sessions)
