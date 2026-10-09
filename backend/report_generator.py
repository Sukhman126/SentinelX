"""
Professional Report Generator.

Builds an enterprise-style PDF penetration test / vulnerability
assessment report from a project's stored hosts + vulnerabilities:
Cover Page, Executive Summary, Methodology, Scope, Findings, Risk
Rating, Remediation, Conclusion.
"""

import datetime
import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
)

from risk import summarize_by_severity
from ai_engine import summarize_findings

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#8B0000"),
    "High": colors.HexColor("#D9534F"),
    "Medium": colors.HexColor("#F0AD4E"),
    "Low": colors.HexColor("#5BC0DE"),
    "Informational": colors.HexColor("#777777"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", fontSize=28, leading=34,
                               alignment=1, spaceAfter=20, textColor=colors.HexColor("#0B2545")))
    styles.add(ParagraphStyle(name="CoverSub", fontSize=14, leading=18,
                               alignment=1, textColor=colors.HexColor("#333333")))
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=16, leading=20,
                               spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#0B2545")))
    styles.add(ParagraphStyle(name="Body", fontSize=10, leading=14))
    return styles


def generate_pdf_report(project, hosts, vulnerabilities, output_path: str) -> str:
    styles = _styles()
    doc = SimpleDocTemplate(output_path, pagesize=letter,
                             topMargin=0.8 * inch, bottomMargin=0.8 * inch)
    story = []

    # ---------- Cover Page ----------
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("SentinelX Security Assessment Report", styles["CoverTitle"]))
    story.append(Paragraph(project.name, styles["CoverSub"]))
    if project.client_name:
        story.append(Paragraph(f"Prepared for: {project.client_name}", styles["CoverSub"]))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(datetime.date.today().strftime("%B %d, %Y"), styles["CoverSub"]))
    story.append(Paragraph("CONFIDENTIAL - For authorized recipients only", styles["CoverSub"]))
    story.append(PageBreak())

    # ---------- Executive Summary ----------
    severity_counts = summarize_by_severity(vulnerabilities)
    findings_text = "\n".join(
        f"{v.severity} - {v.title} ({v.cve_id or 'N/A'}) on host {v.host_id}"
        for v in vulnerabilities
    ) or "No findings recorded."
    exec_summary = summarize_findings(findings_text, executive=True)

    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
    story.append(Paragraph(exec_summary, styles["Body"]))
    story.append(Spacer(1, 0.2 * inch))

    summary_table_data = [["Severity", "Count"]] + [[k, str(v)] for k, v in severity_counts.items()]
    t = Table(summary_table_data, colWidths=[2.5 * inch, 2.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B2545")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(t)
    story.append(PageBreak())

    # ---------- Methodology & Scope ----------
    story.append(Paragraph("Methodology", styles["SectionHeading"]))
    story.append(Paragraph(
        "Assessment data was collected using industry-standard scanning tools "
        "(Nmap and/or Nessus) executed within an authorized lab/test environment. "
        "Results were imported into SentinelX, which correlates service "
        "fingerprints against known CVEs, calculates a composite risk score per "
        "finding (CVSS combined with exploit availability, exposure, and business "
        "impact), and generates this report.", styles["Body"]))

    story.append(Paragraph("Scope", styles["SectionHeading"]))
    scope_list = ", ".join(sorted(set(h.ip_address for h in hosts))) or "No hosts in scope."
    story.append(Paragraph(f"In-scope hosts: {scope_list}", styles["Body"]))
    story.append(PageBreak())

    # ---------- Findings ----------
    story.append(Paragraph("Findings", styles["SectionHeading"]))
    findings_sorted = sorted(vulnerabilities, key=lambda v: v.risk_score, reverse=True)

    if not findings_sorted:
        story.append(Paragraph("No vulnerabilities were identified.", styles["Body"]))

    for v in findings_sorted:
        color = SEVERITY_COLORS.get(v.severity, colors.grey)
        heading_style = ParagraphStyle(
            name="FindingHeading", parent=styles["Body"], fontSize=12,
            textColor=color, spaceBefore=14, spaceAfter=4, leading=15,
        )
        story.append(Paragraph(f"[{v.severity}] {v.title}", heading_style))
        meta = f"CVE: {v.cve_id or 'N/A'}  |  CVSS: {v.cvss_score}  |  Risk Score: {v.risk_score}/10  |  Port: {v.port or 'N/A'}"
        story.append(Paragraph(meta, styles["Body"]))
        story.append(Paragraph(f"Description: {v.description or 'N/A'}", styles["Body"]))
        story.append(Paragraph(f"Remediation: {v.remediation or 'Review and patch affected service.'}", styles["Body"]))

    story.append(PageBreak())

    # ---------- Conclusion ----------
    story.append(Paragraph("Conclusion", styles["SectionHeading"]))
    story.append(Paragraph(
        "This assessment identified the findings summarized above. Remediation "
        "should be prioritized by composite risk score, with particular attention "
        "to critical and high-severity findings on internet-facing assets. "
        "SentinelX recommends a follow-up assessment after remediation to validate "
        "that identified issues have been resolved.", styles["Body"]))

    doc.build(story)
    return output_path
