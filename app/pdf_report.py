"""Customer-facing PDF report builder for AWS assessment scans."""

from __future__ import annotations

import io
from datetime import datetime
from xml.sax.saxutils import escape

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        KeepTogether,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    REPORTLAB_AVAILABLE = True
    SEV_COLORS = {
        "CRITICAL": colors.HexColor("#C82F3A"),
        "HIGH": colors.HexColor("#D97A1E"),
        "MEDIUM": colors.HexColor("#B8860B"),
        "LOW": colors.HexColor("#0C8F66"),
        "INFO": colors.HexColor("#1F58BC"),
    }
except ImportError:
    REPORTLAB_AVAILABLE = False
    SEV_COLORS = {}

SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

SERVICE_SHEET_ORDER = [
    "IAM Users",
    "IAM Roles",
    "IAM Password Policy",
    "EC2 Instances",
    "Security Groups",
    "EBS Volumes",
    "EBS Snapshots",
    "AMIs",
    "Elastic IPs",
    "S3 Buckets",
    "RDS Instances",
    "Aurora Clusters",
    "DynamoDB Tables",
    "ElastiCache Clusters",
    "Load Balancers",
    "VPC Info",
    "Route53 Zones",
    "VPN Connections",
    "CloudFront",
    "EKS Clusters",
    "ECS Clusters",
    "OpenSearch Domains",
    "Redshift Clusters",
    "KMS Keys",
    "Secrets Manager",
    "AWS WAF",
    "GuardDuty",
    "CloudTrail Events",
    "CloudWatch Alarms",
    "AWS Backup Jobs",
    "Cost Summary",
    "Daily Total Cost",
    "Cost Anomalies",
]

MAX_SERVICE_ROWS = None  # Render all available rows in the PDF tables by default


def _esc(value) -> str:
    return escape(str(value if value is not None else ""))


def _p(text: str, style) -> Paragraph:
    return Paragraph(_esc(text).replace("\n", "<br/>"), style)


def _count_severities(findings):
    counts = {level: 0 for level in SEV_ORDER}
    for finding in findings:
        level = finding.get("Severity", "INFO")
        counts[level] = counts.get(level, 0) + 1
    return counts


def _executive_summary(findings, sev_counts):
    total = len(findings)
    critical = sev_counts["CRITICAL"]
    high = sev_counts["HIGH"]
    if critical or high:
        risk = (
            f"This assessment identified {critical} critical and {high} high-severity issues "
            "that should be prioritized for remediation."
        )
    elif total:
        risk = (
            f"No critical or high findings were detected, but {total} medium, low, or "
            "informational items still deserve review."
        )
    else:
        risk = "No security findings were recorded during this assessment."
    return (
        "This report summarizes the AWS account posture across identity, compute, storage, "
        "networking, database, monitoring, and cost-related controls. Each finding includes "
        "the affected resource, the issue observed, and a recommended remediation action. "
        f"{risk} Use the Excel export for full raw inventory details."
    )


def _overview_rows(report_data):
    rows = report_data.get("Account Overview", [])
    parsed = []
    for row in rows:
        category = str(row.get("Category", "")).strip()
        metric = str(row.get("Metric", "")).strip()
        value = str(row.get("Value", "")).strip()
        recommendation = str(row.get("Recommendation", "")).strip()
        if category.startswith("──"):
            parsed.append(("section", category.replace("──", "").strip()))
        elif metric or value:
            parsed.append(("row", metric, value, recommendation))
    return parsed


def _service_sections(report_data):
    skip = {"Account Overview", "Cost Overview (raw)"}
    ordered = [name for name in SERVICE_SHEET_ORDER if name in report_data and name not in skip]
    for name in report_data:
        if name not in skip and name not in ordered:
            ordered.append(name)
    sections = []
    for name in ordered:
        rows = report_data.get(name, [])
        if isinstance(rows, list) and rows:
            sections.append((name, rows))
    return sections


def _table_from_records(records, styles, body_style, max_rows=MAX_SERVICE_ROWS):
    if not records:
        return None

    columns = []
    for record in records:
        if isinstance(record, dict):
            for key in record.keys():
                if key not in columns:
                    columns.append(key)
    if not columns:
        return None

    shown = records if max_rows is None else records[:max_rows]
    header = [_p(col, styles["TableHead"]) for col in columns]
    body = []
    for record in shown:
        row = []
        for col in columns:
            value = record.get(col, "") if isinstance(record, dict) else ""
            if isinstance(value, datetime):
                value = value.strftime("%Y-%m-%d %H:%M")
            row.append(_p(str(value), body_style))
        body.append(row)

    data = [header, *body]
    col_count = len(columns)
    width = 7.0 * inch / max(col_count, 1)
    table = Table(data, colWidths=[width] * col_count, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F58BC")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D7E3F4")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFF")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table, len(records), len(shown)


def _footer(canvas, doc, title):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#556B84"))
    canvas.drawString(doc.leftMargin, 0.45 * inch, title)
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 0.45 * inch, f"Page {doc.page}")
    canvas.restoreState()


def generate_assessment_pdf(assessment, customer_name: str | None = None) -> bytes:
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("PDF generation requires reportlab. Install reportlab or remove PDF export.")

    account_label = customer_name or assessment.account_name or "N/A"
    account_id = assessment.account_id
    regions = assessment.regions
    findings = list(assessment.findings)
    report_data = assessment.report_data
    sev_counts = _count_severities(findings)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    doc_title = f"AWS Assessment - {account_label}"

    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=letter,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.75 * inch,
        title=doc_title,
        author="AWS Assessment Scanner",
    )

    base = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=28,
            textColor=colors.HexColor("#1F58BC"),
            alignment=TA_LEFT,
            spaceAfter=8,
        ),
        "Subtitle": ParagraphStyle(
            "Subtitle",
            parent=base["Normal"],
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#556B84"),
            spaceAfter=4,
        ),
        "Section": ParagraphStyle(
            "Section",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#102240"),
            spaceBefore=14,
            spaceAfter=8,
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#102240"),
            spaceAfter=6,
        ),
        "Small": ParagraphStyle(
            "Small",
            parent=base["Normal"],
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#556B84"),
            spaceAfter=4,
        ),
        "TableHead": ParagraphStyle(
            "TableHead",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
        ),
        "FindingTitle": ParagraphStyle(
            "FindingTitle",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#102240"),
            spaceAfter=4,
        ),
    }

    story = []

    story.append(_p("AWS Security Assessment Report", styles["Title"]))
    story.append(_p(f"Customer account: {account_label}", styles["Subtitle"]))
    story.append(_p(f"AWS account ID: {account_id}", styles["Subtitle"]))
    story.append(_p(f"Regions scanned: {len(regions)}", styles["Subtitle"]))
    story.append(_p(f"Report generated: {generated_at}", styles["Subtitle"]))
    story.append(Spacer(1, 0.18 * inch))
    story.append(_p(_executive_summary(findings, sev_counts), styles["Body"]))

    summary_data = [
        [_p("Severity", styles["TableHead"]), _p("Count", styles["TableHead"])],
        *[
            [_p(level.title(), styles["Body"]), _p(str(sev_counts[level]), styles["Body"])]
            for level in SEV_ORDER
        ],
        [_p("Total findings", styles["FindingTitle"]), _p(str(len(findings)), styles["FindingTitle"])],
    ]
    summary_table = Table(summary_data, colWidths=[2.4 * inch, 1.2 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F58BC")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D7E3F4")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#F7FAFF")]),
                ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#EEF5FF")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(Spacer(1, 0.12 * inch))
    story.append(_p("Findings summary", styles["Section"]))
    story.append(summary_table)

    story.append(PageBreak())
    story.append(_p("Account overview", styles["Section"]))
    story.append(
        _p(
            "The overview below highlights the most important inventory and risk metrics collected "
            "during the scan. Recommendations are included where immediate action is suggested.",
            styles["Body"],
        )
    )

    overview_data = []
    for item in _overview_rows(report_data):
        if item[0] == "section":
            overview_data.append([_p(item[1], styles["FindingTitle"]), _p("", styles["Body"]), _p("", styles["Body"])])
        else:
            _, metric, value, recommendation = item
            overview_data.append(
                [
                    _p(metric, styles["Body"]),
                    _p(value, styles["Body"]),
                    _p(recommendation, styles["Small"]),
                ]
            )

    if overview_data:
        overview_table = Table(
            overview_data,
            colWidths=[2.5 * inch, 1.5 * inch, 3.0 * inch],
            repeatRows=0,
        )
        overview_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D7E3F4")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FCFDFF")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        story.append(Spacer(1, 0.08 * inch))
        story.append(overview_table)
    else:
        story.append(_p("No account overview data was available.", styles["Body"]))

    story.append(PageBreak())
    story.append(_p("Security findings and recommendations", styles["Section"]))
    story.append(
        _p(
            "Findings are grouped by severity. Address critical and high items first, then work "
            "through medium and low findings during regular hardening cycles.",
            styles["Body"],
        )
    )

    sorted_findings = sorted(
        findings,
        key=lambda item: SEV_ORDER.index(item["Severity"]) if item["Severity"] in SEV_ORDER else 99,
    )

    if not sorted_findings:
        story.append(_p("No findings were recorded for this assessment.", styles["Body"]))
    else:
        current_level = None
        for index, finding in enumerate(sorted_findings, start=1):
            level = finding.get("Severity", "INFO")
            if level != current_level:
                current_level = level
                story.append(Spacer(1, 0.08 * inch))
                story.append(_p(f"{level.title()} findings ({sev_counts.get(level, 0)})", styles["Section"]))

            block = [
                _p(
                    f"{index}. [{level}] {finding.get('Category', 'General')} · {finding.get('Resource', 'N/A')}",
                    styles["FindingTitle"],
                ),
                _p(f"Issue: {finding.get('Issue', '')}", styles["Body"]),
                _p(f"Recommendation: {finding.get('Recommendation', '')}", styles["Body"]),
                Spacer(1, 0.06 * inch),
            ]
            color = SEV_COLORS.get(level, colors.HexColor("#D7E3F4"))
            finding_table = Table([[block]], colWidths=[6.9 * inch])
            finding_table.setStyle(
                TableStyle(
                    [
                        ("BOX", (0, 0), (-1, -1), 0.6, color),
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FCFDFF")),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            story.append(KeepTogether(finding_table))

    story.append(PageBreak())
    story.append(_p("Detailed service inventory", styles["Section"]))
    story.append(
        _p(
            "The tables below provide customer-readable snapshots of the AWS resources reviewed "
            "during this assessment. Full row-level detail is available in the Excel export.",
            styles["Body"],
        )
    )

    for section_name, records in _service_sections(report_data):
        built = _table_from_records(records, styles, styles["Body"])
        if not built:
            continue
        table, total_rows, shown_rows = built
        story.append(Spacer(1, 0.1 * inch))
        story.append(_p(section_name, styles["Section"]))
        story.append(_p(f"Records reviewed: {total_rows}", styles["Small"]))
        story.append(table)
        if shown_rows < total_rows:
            story.append(
                _p(
                    f"Showing {shown_rows} of {total_rows} records. Download the XLSX report for the complete dataset.",
                    styles["Small"],
                )
            )

    story.append(Spacer(1, 0.2 * inch))
    story.append(
        _p(
            "Disclaimer: This report reflects point-in-time configuration and security posture "
            "observations from automated AWS API checks. Validate recommendations against your "
            "operational requirements before applying changes in production.",
            styles["Small"],
        )
    )

    doc.build(
        story,
        onFirstPage=lambda canvas, document: _footer(canvas, document, doc_title),
        onLaterPages=lambda canvas, document: _footer(canvas, document, doc_title),
    )
    output.seek(0)
    return output.getvalue()
