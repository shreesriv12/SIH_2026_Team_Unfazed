from tools.evaluate_benchmark import evaluate

def test_empty_benchmark_has_safe_metrics():
    result = evaluate({"captures": []})
    assert result["precision"] == 0 and result["recall"] == 0
