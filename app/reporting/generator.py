"""
AuthGuard Multi-Format Canonical Reporting Engine
=================================================
Generates audit-ready HTML, PDF, and JSON reports from canonical database results.
Calculates SHA-256 integrity hashes for each exported artifact.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from jinja2 import Template
from sqlalchemy.orm import Session

from app.config import settings
from app.core.logging import logger
from app.models.assessment import Assessment
from app.models.finding import Finding
from app.models.report import Report


# Standard ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AuthGuard Security Assessment Report - {{ assessment.name }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }
        .container { max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 36px; border: 1px solid #334155; }
        .header { border-bottom: 2px solid #3b82f6; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
        h1 { margin: 0; color: #60a5fa; font-size: 26px; }
        .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: #0f172a; padding: 15px; border-radius: 8px; border: 1px solid #334155; text-align: center; }
        .stat-num { font-size: 24px; font-weight: bold; margin-bottom: 5px; }
        .stat-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; }
        .sev-Critical { color: #ef4444; }
        .sev-High { color: #f97316; }
        .sev-Medium { color: #eab308; }
        .sev-Low { color: #3b82f6; }
        .finding-card { background: #0f172a; border-left: 5px solid #3b82f6; padding: 20px; margin-bottom: 20px; border-radius: 0 8px 8px 0; border-top: 1px solid #334155; border-right: 1px solid #334155; border-bottom: 1px solid #334155; }
        .finding-card.Critical { border-left-color: #ef4444; }
        .finding-card.High { border-left-color: #f97316; }
        .finding-card.Medium { border-left-color: #eab308; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
        .badge.Critical { background: #ef444422; color: #ef4444; border: 1px solid #ef4444; }
        .badge.High { background: #f9731622; color: #f97316; border: 1px solid #f97316; }
        .badge.Medium { background: #eab30822; color: #eab308; border: 1px solid #eab308; }
        .badge.Low { background: #3b82f622; color: #3b82f6; border: 1px solid #3b82f6; }
        .section-title { font-size: 20px; color: #f1f5f9; margin-top: 35px; margin-bottom: 15px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
        p { line-height: 1.6; color: #cbd5e1; }
        code { background: #334155; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-family: monospace; }
        .footer { margin-top: 40px; text-align: center; font-size: 12px; color: #64748b; border-top: 1px solid #334155; padding-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>AuthGuard Security Assessment Report</h1>
                <p style="margin: 5px 0 0 0; color: #94a3b8;">Target: <code>{{ target.base_url }}</code></p>
            </div>
            <div>
                <span class="badge" style="background:#3b82f622; color:#60a5fa; border:1px solid #3b82f6;">{{ assessment.status | upper }}</span>
            </div>
        </div>

        <div class="meta-grid">
            <div class="stat-card">
                <div class="stat-num">{{ assessment.total_tests }}</div>
                <div class="stat-label">Total Tests Executed</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: #22c55e;">{{ assessment.passed_tests }}</div>
                <div class="stat-label">Passed Checks</div>
            </div>
            <div class="stat-card">
                <div class="stat-num" style="color: #ef4444;">{{ findings|length }}</div>
                <div class="stat-label">Identified Weaknesses</div>
            </div>
            <div class="stat-card">
                <div class="stat-num">{{ assessment.requests_used }} / {{ assessment.request_budget }}</div>
                <div class="stat-label">Requests Used</div>
            </div>
        </div>

        <h2 class="section-title">Executive Summary</h2>
        <p>
            AuthGuard performed an authorized security evaluation of the authentication and verification controls on <strong>{{ target.hostname }}</strong>.
            The audit evaluated One-Time Password (OTP) verification resilience, brute-force resistance and login rate limiting, and server-side CAPTCHA enforcement.
        </p>

        <h2 class="section-title">Assessment Findings & Evidence ({{ findings|length }})</h2>
        {% if findings %}
            {% for f in findings %}
            <div class="finding-card {{ f.severity }}">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px;">
                    <h3 style="margin:0; color:#f8fafc; font-size:18px;">{{ f.title }}</h3>
                    <span class="badge {{ f.severity }}">{{ f.severity }} (CVSS {{ f.cvss_score }})</span>
                </div>
                <p><strong>Endpoint:</strong> <code>{{ f.affected_endpoint }}</code> | <strong>Module:</strong> {{ f.module | upper }}</p>
                <p>{{ f.description }}</p>
                <div style="background:#090d16; padding:12px; border-radius:6px; margin:10px 0; font-size:13px;">
                    <div style="color:#ef4444; margin-bottom:4px;"><strong>Observed Behavior:</strong> {{ f.actual_behavior }}</div>
                    <div style="color:#22c55e;"><strong>Expected Security Standard:</strong> {{ f.expected_behavior }}</div>
                </div>
                <p><strong>Impact:</strong> {{ f.potential_impact }}</p>
                <p style="color:#38bdf8;"><strong>Remediation:</strong> {{ f.remediation }}</p>
            </div>
            {% endfor %}
        {% else %}
            <p style="color: #22c55e;">No security vulnerabilities were identified in the assessed authentication flows.</p>
        {% endif %}

        <div class="footer">
            Generated by AuthGuard Platform &bull; Assessment ID #{{ assessment.id }} &bull; {{ timestamp }}
        </div>
    </div>
</body>
</html>
"""


def compute_file_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_json_report(assessment: Assessment, target: any, findings: List[Finding]) -> Path:
    """Generate canonical JSON report."""
    data = {
        "assessment_id": assessment.id,
        "name": assessment.name,
        "status": assessment.status,
        "started_at": assessment.started_at.isoformat() if assessment.started_at else None,
        "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
        "target": {
            "id": target.id,
            "name": target.name,
            "base_url": target.base_url,
            "hostname": target.hostname,
        },
        "telemetry": {
            "total_tests": assessment.total_tests,
            "passed_tests": assessment.passed_tests,
            "failed_tests": assessment.failed_tests,
            "requests_used": assessment.requests_used,
            "request_budget": assessment.request_budget,
        },
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "module": f.module,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "endpoint": f.affected_endpoint,
                "description": f.description,
                "expected": f.expected_behavior,
                "actual": f.actual_behavior,
                "impact": f.potential_impact,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }

    filename = f"report_assessment_{assessment.id}.json"
    file_path = settings.REPORTS_DIR / filename
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return file_path


def generate_html_report(assessment: Assessment, target: any, findings: List[Finding]) -> Path:
    """Render HTML report via Jinja2 template."""
    tmpl = Template(HTML_REPORT_TEMPLATE)
    rendered = tmpl.render(
        assessment=assessment,
        target=target,
        findings=findings,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    filename = f"report_assessment_{assessment.id}.html"
    file_path = settings.REPORTS_DIR / filename
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    return file_path


def generate_pdf_report(assessment: Assessment, target: any, findings: List[Finding]) -> Path:
    """Compile PDF report using ReportLab."""
    filename = f"report_assessment_{assessment.id}.pdf"
    file_path = settings.REPORTS_DIR / filename

    doc = SimpleDocTemplate(str(file_path), pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading1"],
        fontSize=20,
        textColor=colors.HexColor("#1e3a8a"),
        spaceAfter=12,
    )
    story.append(Paragraph("AuthGuard Security Assessment Report", title_style))
    story.append(Paragraph(f"<b>Target:</b> {target.base_url} | <b>Status:</b> {assessment.status.upper()}", styles["Normal"]))
    story.append(Spacer(1, 16))

    # Summary Table
    summary_data = [
        ["Metric", "Value"],
        ["Assessment Name", assessment.name],
        ["Target Host", target.hostname],
        ["Total Tests Run", str(assessment.total_tests)],
        ["Passed Checks", str(assessment.passed_tests)],
        ["Findings Identified", str(len(findings))],
        ["Requests Budget / Used", f"{assessment.requests_used} / {assessment.request_budget}"],
    ]
    t = Table(summary_data, colWidths=[200, 300])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))

    # Findings Section
    story.append(Paragraph("<b>Security Findings & Weaknesses</b>", styles["Heading2"]))
    story.append(Spacer(1, 10))

    if findings:
        for f in findings:
            story.append(Paragraph(f"<b>{f.title}</b> ({f.severity} - CVSS {f.cvss_score})", styles["Heading3"]))
            story.append(Paragraph(f"<b>Endpoint:</b> {f.affected_endpoint}", styles["Normal"]))
            story.append(Paragraph(f"<b>Description:</b> {f.description}", styles["Normal"]))
            story.append(Paragraph(f"<b>Remediation:</b> {f.remediation}", styles["Italic"]))
            story.append(Spacer(1, 12))
    else:
        story.append(Paragraph("No security vulnerabilities were identified in the assessed endpoints.", styles["Normal"]))

    doc.build(story)
    return file_path


def generate_all_reports(assessment_id: int, db: Session) -> Dict[str, str]:
    """Coordinates generation of HTML, PDF, and JSON reports and records them in DB."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        return {}

    target = assessment.target
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()

    paths = {}

    # 1. JSON
    json_path = generate_json_report(assessment, target, findings)
    json_hash = compute_file_sha256(json_path)
    r_json = Report(
        assessment_id=assessment.id,
        report_format="json",
        filename=json_path.name,
        file_path=str(json_path),
        file_hash=json_hash,
    )
    db.add(r_json)
    paths["json"] = str(json_path)

    # 2. HTML
    html_path = generate_html_report(assessment, target, findings)
    html_hash = compute_file_sha256(html_path)
    r_html = Report(
        assessment_id=assessment.id,
        report_format="html",
        filename=html_path.name,
        file_path=str(html_path),
        file_hash=html_hash,
    )
    db.add(r_html)
    paths["html"] = str(html_path)

    # 3. PDF
    pdf_path = generate_pdf_report(assessment, target, findings)
    pdf_hash = compute_file_sha256(pdf_path)
    r_pdf = Report(
        assessment_id=assessment.id,
        report_format="pdf",
        filename=pdf_path.name,
        file_path=str(pdf_path),
        file_hash=pdf_hash,
    )
    db.add(r_pdf)
    paths["pdf"] = str(pdf_path)

    db.commit()
    logger.info(f"All reports generated for assessment {assessment_id}")
    return paths
