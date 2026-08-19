"""Builds a PDF report from a completed ScanResult using reportlab."""
from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#7f1d1d"),
    "high": colors.HexColor("#b91c1c"),
    "medium": colors.HexColor("#b45309"),
    "low": colors.HexColor("#1d4ed8"),
    "info": colors.HexColor("#374151"),
}


def build_pdf(scan_result) -> bytes:
    """scan_result: api.models.ScanResult (or matching dict-like object)."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=LETTER, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], fontSize=20)
    h2 = styles["Heading2"]
    body = styles["BodyText"]

    story = []
    story.append(Paragraph("Web Application Vulnerability Scan Report", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Target: {scan_result.target_url}", body))
    story.append(Paragraph(f"Scan ID: {scan_result.scan_id}", body))
    story.append(Paragraph(f"Started: {scan_result.started_at}", body))
    story.append(Paragraph(f"Finished: {scan_result.finished_at}", body))
    story.append(Paragraph(f"Pages crawled: {scan_result.pages_crawled}", body))
    story.append(Spacer(1, 12))

    # Summary table
    summary = scan_result.summary
    data = [["Severity", "Count"]] + [[k.capitalize(), str(v)] for k, v in summary.items()]
    table = Table(data, colWidths=[2 * inch, 1 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))

    story.append(Paragraph("Findings", h2))
    if not scan_result.findings:
        story.append(Paragraph("No findings.", body))

    for f in sorted(scan_result.findings, key=lambda x: list(SEVERITY_COLORS).index(x.severity.value)):
        sev_style = ParagraphStyle(
            "Sev", parent=body, textColor=SEVERITY_COLORS.get(f.severity.value, colors.black),
            fontName="Helvetica-Bold",
        )
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"[{f.severity.value.upper()}] {f.title}", sev_style))
        story.append(Paragraph(f"URL: {f.url}", body))
        story.append(Paragraph(f"Description: {f.description}", body))
        if f.evidence:
            story.append(Paragraph(f"Evidence: {f.evidence}", body))
        story.append(Paragraph(f"Remediation: {f.remediation}", body))

    doc.build(story)
    return buffer.getvalue()
