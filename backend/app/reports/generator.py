"""
Professional Security Assessment Report Generator.
Generates comprehensive Executive Summaries and Technical Reports in HTML, PDF, Markdown, and JSON.
Fully covers enterprise DAST audit deliverables.
"""

import os
import json
import io
import html
from typing import List, Dict, Any
from ..evidence.models import Finding, AssessmentStats, Endpoint
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


def _clean_pdf_text(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val), quote=False)


class ReportGenerator:
    """
    Generates auditor-grade security reports matching industry standard DAST criteria.
    """

    @classmethod
    def generate_csv_report(cls, findings: List[Finding], stats: AssessmentStats, target: str) -> str:
        """Exports full findings ledger as an auditor-grade CSV spreadsheet."""
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Finding_ID", "Title", "Severity", "CVSS_Score", "CVSS_Vector",
            "Category", "Affected_Component", "Status", "Confidence",
            "Retest_Status", "Business_Impact", "Remediation"
        ])
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            cat = f.category.value if hasattr(f.category, 'value') else str(f.category)
            stat = f.status.value if hasattr(f.status, 'value') else str(f.status)
            writer.writerow([
                f.id,
                f.title,
                sev,
                f.cvss_score,
                f.cvss_vector,
                cat,
                f.affected_component,
                stat,
                f.confidence,
                f.retest_status or "PENDING",
                (f.business_impact or "").replace("\n", " "),
                (f.remediation_recommendations or "").replace("\n", " ")
            ])
        return output.getvalue()

    @classmethod
    def generate_json_report(cls, findings: List[Finding], stats: AssessmentStats, target: str) -> str:
        """Exports full report as structured JSON."""
        data = {
            "assessment_title": "WorldKavach Autonomous DAST Security Assessment",
            "target": target,
            "statistics": stats.model_dump(),
            "findings_count": len(findings),
            "findings": [f.model_dump() for f in findings]
        }
        return json.dumps(data, indent=2)

    @classmethod
    def generate_markdown_report(cls, findings: List[Finding], stats: AssessmentStats, target: str) -> str:
        """Generates GitHub-flavored markdown report."""
        md = []
        md.append("# WorldKavach Autonomous DAST Security Assessment Report")
        md.append(f"**Target System:** `{target}`  \n**Audit Reference:** SEC-DAST-2026-WK  \n**Status:** COMPLETED  \n")
        md.append("## 1. Executive Summary")
        md.append(f"- **Endpoints Discovered:** {stats.endpoints_discovered}")
        md.append(f"- **API Endpoints:** {stats.api_endpoints}")
        md.append(f"- **Candidates Identified:** {stats.candidates_count}")
        md.append(f"- **Findings Verified with Evidence:** {stats.verified_count}")
        md.append(f"- **False Positives Rejected:** {stats.rejected_count}")
        md.append(f"- **Critical:** {stats.risk_critical} | **High:** {stats.risk_high} | **Medium:** {stats.risk_medium} | **Low:** {stats.risk_low}\n")

        md.append("## 2. Detailed Technical Findings & Proof-of-Concepts\n")

        for idx, f in enumerate(findings, 1):
            md.append(f"### Finding {idx}: {f.title}")
            md.append(f"- **ID:** `{f.id}`")
            md.append(f"- **Category:** {f.category.value}")
            md.append(f"- **Severity:** **{f.severity.value}** (CVSS v3.1: `{f.cvss_score}` - `{f.cvss_vector}`)")
            md.append(f"- **Affected Component:** `{f.affected_component}`")
            md.append(f"- **Status:** `{f.status.value}` (Confidence: {int(f.confidence * 100)}%)\n")

            md.append("#### Description")
            md.append(f"{f.description}\n")

            md.append("#### Steps to Reproduce")
            for step in f.steps_to_reproduce:
                md.append(f"- {step}")
            md.append("")

            md.append("#### Proof of Concept")
            md.append(f"```bash\n{f.poc_code}\n```\n")

            if f.evidence:
                md.append("#### Live HTTP Evidence Trace")
                md.append(f"- **Target URL:** `{f.evidence.method} {f.evidence.url}`")
                md.append(f"- **HTTP Status Code:** `{f.evidence.response_status}` ({f.evidence.duration_ms} ms)")
                md.append("```http")
                md.append(f"HTTP Response Body Snippet:\n{f.evidence.response_body[:400]}")
                md.append("```\n")

            md.append("#### Business Impact")
            md.append(f"{f.business_impact}\n")

            md.append("#### Remediation Recommendations")
            md.append(f"{f.remediation_recommendations}\n")

            if f.remediation_diff:
                md.append("#### Proposed Code Patch (Diff)")
                md.append(f"```diff\n{f.remediation_diff}\n```\n")

            if f.retest_status:
                md.append(f"#### Re-test Verification: **{f.retest_status}**\n")

            md.append("---\n")
        return "\n".join(md)

    @classmethod
    def generate_html_report(cls, findings: List[Finding], stats: AssessmentStats, target: str) -> str:
        """Generates sleek, print-friendly, responsive HTML report."""
        findings_html = ""
        for f in findings:
            badge_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
                "INFORMATIONAL": "#64748b"
            }.get(f.severity.value, "#64748b")

            status_badge_color = "#10b981" if "VERIFIED" in f.status.value or "FIX" in f.status.value else "#64748b"

            steps_li = "".join([f"<li>{s}</li>" for s in f.steps_to_reproduce])

            evidence_box = ""
            if f.evidence:
                evidence_box = f"""
                <div class="evidence-box">
                    <h4>Captured Live HTTP Evidence Trace</h4>
                    <p><strong>Endpoint:</strong> <code>{f.evidence.method} {f.evidence.url}</code> &nbsp;|&nbsp; <strong>Status:</strong> <code>{f.evidence.response_status}</code> &nbsp;|&nbsp; <strong>Latency:</strong> {f.evidence.duration_ms}ms</p>
                    <pre><code>{f.evidence.response_body[:500]}</code></pre>
                </div>
                """

            diff_box = ""
            if f.remediation_diff:
                diff_box = f"""
                <div class="diff-box">
                    <h4>Remediation Code Patch (Unified Diff)</h4>
                    <pre><code class="diff">{f.remediation_diff}</code></pre>
                </div>
                """

            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="badge" style="background:{badge_color}">{f.severity.value} ({f.cvss_score})</span>
                    <span class="badge" style="background:{status_badge_color}">{f.status.value}</span>
                    <h3 class="finding-title">{f.title}</h3>
                </div>
                <div class="meta-row">
                    <span><strong>ID:</strong> {f.id}</span>
                    <span><strong>Category:</strong> {f.category.value}</span>
                    <span><strong>Component:</strong> <code>{f.affected_component}</code></span>
                    <span><strong>CVSS Vector:</strong> <code>{f.cvss_vector}</code></span>
                </div>
                <div class="section-block">
                    <h4>Description</h4>
                    <p>{f.description}</p>
                </div>
                <div class="section-block">
                    <h4>Steps to Reproduce</h4>
                    <ol>{steps_li}</ol>
                </div>
                <div class="section-block">
                    <h4>Controlled Proof of Concept</h4>
                    <pre><code>{f.poc_code}</code></pre>
                </div>
                {evidence_box}
                <div class="section-block">
                    <h4>Business Impact</h4>
                    <p>{f.business_impact}</p>
                </div>
                <div class="section-block">
                    <h4>Remediation Guidance</h4>
                    <p>{f.remediation_recommendations}</p>
                </div>
                {diff_box}
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>World Monitor Autonomous DAST Security Assessment Report</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f17; color: #e2e8f0; margin: 0; padding: 2rem; line-height: 1.6; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    .header {{ background: #131b2e; border: 1px solid #1e293b; padding: 2rem; border-radius: 8px; margin-bottom: 2rem; }}
    h1 {{ margin: 0 0 0.5rem 0; color: #38bdf8; font-size: 1.8rem; }}
    .subtitle {{ color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.5rem; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 1rem; margin-top: 1rem; }}
    .stat-card {{ background: #1e293b; padding: 1rem; border-radius: 6px; text-align: center; border-left: 3px solid #38bdf8; }}
    .stat-val {{ font-size: 1.6rem; font-weight: 700; color: #f8fafc; }}
    .stat-label {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }}
    .finding-card {{ background: #131b2e; border: 1px solid #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }}
    .finding-header {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.75rem; }}
    .finding-title {{ margin: 0; font-size: 1.25rem; color: #f8fafc; }}
    .badge {{ font-size: 0.75rem; font-weight: 600; padding: 0.2rem 0.6rem; border-radius: 4px; color: #fff; text-transform: uppercase; }}
    .meta-row {{ display: flex; gap: 1.5rem; flex-wrap: wrap; font-size: 0.85rem; color: #94a3b8; padding-bottom: 0.75rem; border-bottom: 1px solid #1e293b; margin-bottom: 1rem; }}
    .section-block {{ margin-bottom: 1rem; }}
    h4 {{ margin: 0.5rem 0 0.25rem 0; font-size: 0.95rem; color: #38bdf8; text-transform: uppercase; letter-spacing: 0.05em; }}
    p, ol {{ margin: 0 0 0.5rem 0; font-size: 0.95rem; color: #cbd5e1; }}
    ol {{ padding-left: 1.2rem; }}
    pre {{ background: #070a10; border: 1px solid #1e293b; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #38bdf8; font-family: monospace; font-size: 0.85rem; }}
    .evidence-box {{ background: #0d1526; border-left: 4px solid #10b981; padding: 1rem; border-radius: 4px; margin: 1rem 0; }}
    .diff-box {{ background: #0d1526; border-left: 4px solid #f97316; padding: 1rem; border-radius: 4px; margin: 1rem 0; }}
    @media print {{ body {{ background: #fff; color: #000; padding: 0; }} .header, .finding-card, pre {{ background: #fff; color: #000; border: 1px solid #ccc; }} }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>WorldKavach Autonomous DAST Security Report</h1>
        <div class="subtitle">Evidence-First Automated Security Evaluation & Vulnerability Assessment</div>
        <p><strong>Target:</strong> <code>{target}</code> &nbsp;|&nbsp; <strong>Assessment Architecture:</strong> WorldKavach Evidence DAST + 3-Agent Swarm</p>
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-val">{stats.endpoints_discovered}</div><div class="stat-label">Endpoints</div></div>
            <div class="stat-card"><div class="stat-val">{stats.api_endpoints}</div><div class="stat-label">APIs</div></div>
            <div class="stat-card"><div class="stat-val">{stats.candidates_count}</div><div class="stat-label">Candidates</div></div>
            <div class="stat-card"><div class="stat-val">{stats.verified_count}</div><div class="stat-label">Verified</div></div>
            <div class="stat-card"><div class="stat-val">{stats.rejected_count}</div><div class="stat-label">False Positives</div></div>
            <div class="stat-card"><div class="stat-val" style="color:#ef4444">{stats.risk_high}</div><div class="stat-label">High Severity</div></div>
        </div>
    </div>
    <h2>Verified Vulnerability Deliverables</h2>
    {findings_html}
</div>
</body>
</html>"""
        return html
 
    @classmethod
    def generate_pdf_report(cls, findings: List[Finding], stats: AssessmentStats, target: str) -> bytes:
        """Generates a professional PDF report using ReportLab with strict XML escaping."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            textColor=colors.HexColor('#0284c7'),
            spaceAfter=8
        )
        subtitle_style = ParagraphStyle(
            'SubtitleStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#475569'),
            spaceAfter=15
        )
        heading2_style = ParagraphStyle(
            'Heading2Style',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=12,
            textColor=colors.HexColor('#0f172a'),
            spaceBefore=10,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#1e293b')
        )
        code_style = ParagraphStyle(
            'CodeStyle',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0369a1'),
            backColor=colors.HexColor('#f1f5f9'),
            borderPadding=4
        )

        elements = []
        safe_target = _clean_pdf_text(target)
        elements.append(Paragraph("WorldKavach Autonomous DAST Security Report", title_style))
        elements.append(Paragraph(f"Target: {safe_target} &mdash; Architecture: Evidence-First Agentic DAST", subtitle_style))
        elements.append(Spacer(1, 10))

        # Stats Table
        table_data = [
            ["Metric", "Value", "Metric", "Value"],
            ["Endpoints Discovered", str(stats.endpoints_discovered), "Candidates Identified", str(stats.candidates_count)],
            ["APIs Analyzed", str(stats.api_endpoints), "Verified with Evidence", str(stats.verified_count)],
            ["Authenticated Routes", str(stats.authenticated_routes), "False Positives Rejected", str(stats.rejected_count)],
            ["High Severity Findings", str(stats.risk_high), "Medium Severity Findings", str(stats.risk_medium)],
        ]
        t = Table(table_data, colWidths=[130, 120, 130, 120])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0284c7')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 15))

        if not findings:
            elements.append(Paragraph("No verified vulnerabilities detected for this target scope.", body_style))
            elements.append(Spacer(1, 10))
        else:
            for idx, f in enumerate(findings, 1):
                title = _clean_pdf_text(f.title)
                sev = _clean_pdf_text(f.severity.value if hasattr(f.severity, 'value') else f.severity)
                comp = _clean_pdf_text(f.affected_component)
                stat = _clean_pdf_text(f.status.value if hasattr(f.status, 'value') else f.status)
                desc = _clean_pdf_text(f.description)
                impact = _clean_pdf_text(f.business_impact)
                remed = _clean_pdf_text(f.remediation_recommendations)
                poc = str(f.poc_code or "")[:350]

                elements.append(Paragraph(f"<b>Finding {idx}: {title}</b>", heading2_style))
                elements.append(Paragraph(f"<b>Severity:</b> {sev} (CVSS: {f.cvss_score}) | <b>Component:</b> {comp} | <b>Status:</b> {stat}", body_style))
                elements.append(Spacer(1, 4))
                elements.append(Paragraph(f"<b>Description:</b> {desc}", body_style))
                elements.append(Spacer(1, 4))
                if poc:
                    elements.append(Paragraph("<b>Controlled Proof of Concept:</b>", body_style))
                    elements.append(Preformatted(poc, code_style))
                    elements.append(Spacer(1, 4))
                elements.append(Paragraph(f"<b>Business Impact:</b> {impact}", body_style))
                elements.append(Spacer(1, 4))
                elements.append(Paragraph(f"<b>Remediation:</b> {remed}", body_style))
                elements.append(Spacer(1, 10))

        try:
            doc.build(elements)
        except Exception:
            # Fallback document in case of any unexpected platypus formatting error
            fallback_buffer = io.BytesIO()
            fdoc = SimpleDocTemplate(fallback_buffer, pagesize=letter)
            felements = [
                Paragraph("WorldKavach Security Assessment Summary", title_style),
                Paragraph(f"Target: {safe_target}", subtitle_style),
                t,
                Spacer(1, 15),
                Paragraph(f"Audit completed with {len(findings)} findings recorded. Full details available in JSON/Markdown exports.", body_style)
            ]
            fdoc.build(felements)
            fallback_buffer.seek(0)
            return fallback_buffer.getvalue()

        buffer.seek(0)
        return buffer.getvalue()
