from reports.html_report import render_html_report

def test_html_report_escapes_capture_data():
    output = render_html_report({"file": "<capture>", "sha256": "abc", "findings": [], "sessions": []})
    assert "&lt;capture&gt;" in output
    assert "No deterministic findings" in output
