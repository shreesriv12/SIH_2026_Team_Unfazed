from core.models import AnalysisResult

def test_performance_metrics_are_exported():
    result = AnalysisResult([], 0, "TShark", [], performance={"analysis_time_ms": 12.5})
    assert result.as_dict()["performance"]["analysis_time_ms"] == 12.5
