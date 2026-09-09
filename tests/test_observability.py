from observability import metric_path, safe, valid_request_id


def test_sensitive_log_values_are_redacted():
    output = safe("token=abc password=hunter2 status=failed")
    assert "abc" not in output and "hunter2" not in output
    assert output.count("[REDACTED]") == 2


def test_metric_paths_do_not_include_unique_ids():
    identifier = "123e4567-e89b-12d3-a456-426614174000"
    assert metric_path(f"/api/jobs/{identifier}") == "/api/jobs/{id}"


def test_untrusted_request_id_is_replaced():
    assert valid_request_id("valid-request_1") == "valid-request_1"
    assert valid_request_id("bad request\nvalue") != "bad request\nvalue"
