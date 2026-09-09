from __future__ import annotations

import html
import json
from typing import Any


def render_html_report(report: dict[str, Any]) -> str:
    findings = "".join(f"<li><b>{html.escape(item['severity'])}</b> — {html.escape(item['title'])}<br><small>{html.escape(item['evidence'])}</small></li>" for item in report.get("findings", [])) or "<li>No deterministic findings.</li>"
    sessions = "".join(f"<tr><td>{html.escape(session['session_id'])}</td><td>{html.escape(session['protocol'])}</td><td>{html.escape(session['transition'])}</td><td>{html.escape(session['tls_version'])}</td><td>{session['risk_score']}/100</td><td>{html.escape(session['confidence'])}</td></tr>" for session in report.get("sessions", []))
    raw_json = html.escape(json.dumps(report, indent=2))
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><title>SecureMailScope report</title><style>body{{font:15px Arial;margin:40px;color:#10222c;background:#f3f2ec}}h1{{font-size:42px;margin-bottom:4px}}section{{border-top:1px solid #10222c;padding:18px 0}}table{{border-collapse:collapse;width:100%}}td,th{{text-align:left;padding:9px;border-bottom:1px solid #c9cec5}}li{{padding:10px 0;border-bottom:1px solid #c9cec5}}pre{{background:#10222c;color:#dce7e9;padding:16px;overflow:auto}}small{{color:#536870}}</style></head><body><p>SECUREMAILSCOPE / EVIDENCE REPORT</p><h1>{html.escape(str(report.get('file', 'Network capture')))}</h1><small>SHA-256: {html.escape(str(report.get('sha256', '')))}</small><section><h2>Findings</h2><ul>{findings}</ul></section><section><h2>Canonical sessions</h2><table><thead><tr><th>Session</th><th>Protocol</th><th>Transition</th><th>TLS</th><th>Risk</th><th>Confidence</th></tr></thead><tbody>{sessions}</tbody></table></section><section><h2>Complete evidence data</h2><pre>{raw_json}</pre></section></body></html>"""
