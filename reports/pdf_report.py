from __future__ import annotations
from io import BytesIO
from typing import Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

def render_pdf_report(report: dict[str, Any]) -> bytes:
    stream = BytesIO(); styles = getSampleStyleSheet(); story = [Paragraph("SecureMailScope Evidence Report", styles["Title"]), Paragraph(str(report.get("file", "Network capture")), styles["Heading2"]), Paragraph(f"SHA-256: {report.get('sha256', '')}", styles["Code"]), Spacer(1, 8)]
    story.append(Paragraph("Findings", styles["Heading2"]))
    findings = report.get("findings", [])
    story.extend([Paragraph(f"<b>{item['severity']}</b> - {item['title']}<br/>{item['evidence']}", styles["BodyText"]) for item in findings] or [Paragraph("No deterministic findings.", styles["BodyText"])])
    story += [Spacer(1, 10), Paragraph("Canonical sessions", styles["Heading2"])]
    data = [["Protocol", "Transition", "TLS", "Risk", "Confidence"]] + [[item["protocol"], item["transition"], item["tls_version"], f"{item['risk_score']}/100", item["confidence"]] for item in report.get("sessions", [])]
    table = Table(data, repeatRows=1, colWidths=[25*mm, 55*mm, 25*mm, 20*mm, 28*mm]); table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#10222c")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .25, colors.grey), ("FONTSIZE", (0,0), (-1,-1), 8), ("VALIGN", (0,0), (-1,-1), "TOP"), ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f3f2ec")])]))
    story.append(table); SimpleDocTemplate(stream, pagesize=A4, rightMargin=15*mm, leftMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm).build(story)
    return stream.getvalue()
