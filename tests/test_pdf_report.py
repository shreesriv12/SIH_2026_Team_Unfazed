from reports.pdf_report import render_pdf_report

def test_pdf_report_is_a_valid_pdf():
    content = render_pdf_report({"file": "capture.pcapng", "sha256": "abc", "findings": [], "sessions": []})
    assert content.startswith(b"%PDF")
