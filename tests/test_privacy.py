from privacy import redact
def test_redacts_sensitive_capture_data():
    output = redact("MAIL FROM:<alice@example.com> password=hunter2")
    assert "alice@example.com" not in output and "hunter2" not in output
