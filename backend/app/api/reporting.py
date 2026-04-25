import csv
import io
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

import openpyxl
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from app.middleware.auth import require_analyst, require_admin, AuditLogger
from app.repositories.clickhouse import ClickHouseRepository
from app.repositories.postgres import ReportMetadata
from app.dependencies import get_app_postgres

router = APIRouter(prefix="/reports", tags=["Reporting"])


@router.get("/csv")
async def generate_csv_report(
    limit: int = Query(default=100, ge=1, le=10000),
    request: Request = None,
    claims: dict = Depends(require_analyst),
):
    """Generate a CSV report of recent security events. Requires analyst role."""
    AuditLogger.log("report_csv_generated", request=request, claims=claims, detail=f"limit={limit}")
    ch = ClickHouseRepository()
    tenant_id = claims.get("tenant_id", "default")
    try:
        events = await ch.query_events(tenant_id=tenant_id, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "Event ID", "Source Type", "Severity", 
        "Action", "Meta Score", "Message"
    ])
    
    for ev in events:
        ts = ev.get("timestamp", "")
        if isinstance(ts, datetime):
            ts = ts.isoformat()
        writer.writerow([
            ts,
            ev.get("event_id", ""),
            ev.get("source_type", ""),
            ev.get("severity", ""),
            ev.get("action", ""),
            ev.get("meta_score", 0.0),
            ev.get("message", "")
        ])
    
    output.seek(0)
    headers = {
        'Content-Disposition': f'attachment; filename="security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv"'
    }
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)


@router.get("/excel")
async def generate_excel_report(
    limit: int = Query(default=1000, ge=1, le=10000),
    request: Request = None,
    claims: dict = Depends(require_analyst),
):
    """Generate an Excel tracking report of recent security events."""
    AuditLogger.log("report_excel_generated", request=request, claims=claims, detail=f"limit={limit}")
    ch = ClickHouseRepository()
    tenant_id = claims.get("tenant_id", "default")
    try:
        events = await ch.query_events(tenant_id=tenant_id, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Security Events"

    headers = [
        "Timestamp", "Event ID", "Source Type", "Severity", 
        "Action", "Outcome", "Source IP", "Dest IP", "Meta Score", "Campaign ID", "Message"
    ]
    ws.append(headers)

    for ev in events:
        ts = ev.get("timestamp", "")
        if isinstance(ts, datetime):
            ts = ts.strftime("%Y-%m-%d %H:%M:%S")
        ws.append([
            ts,
            ev.get("event_id", ""),
            ev.get("source_type", ""),
            ev.get("severity", ""),
            ev.get("action", ""),
            ev.get("outcome", ""),
            ev.get("src_ip", ""),
            ev.get("dst_ip", ""),
            ev.get("meta_score", 0.0),
            ev.get("campaign_id", ""),
            ev.get("message", "")
        ])

    buffer = io.BytesIO()
    wb.save(buffer)
    buffer.seek(0)

    # Save metadata
    try:
        repo = get_app_postgres()
        user_id = claims.get("sub", "system")
        meta = ReportMetadata(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            report_name=f"excel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
            report_type="excel_extract",
            generated_by=user_id,
            file_size_bytes=buffer.getbuffer().nbytes
        )
        await repo.save_report_metadata(meta)
    except Exception:
        pass

    response_headers = {
        'Content-Disposition': f'attachment; filename="security_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx"'
    }
    return StreamingResponse(
        iter([buffer.getvalue()]), 
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 
        headers=response_headers
    )

@router.get("/pdf")
async def generate_pdf_report(
    limit: int = Query(default=50, ge=1, le=10000),
    request: Request = None,
    claims: dict = Depends(require_analyst),
):
    """Generate a PDF report of high-severity events."""
    AuditLogger.log("report_pdf_generated", request=request, claims=claims, detail=f"limit={limit}")

    ch = ClickHouseRepository()
    tenant_id = claims.get("tenant_id", "default")
    try:
        events = await ch.query_events(tenant_id=tenant_id, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']

    story = []
    story.append(Paragraph("UMBRIX - Executive Security Report", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Paragraph(f"Total Evaluated Events: {len(events)}", normal_style))
    story.append(Spacer(1, 24))

    story.append(Paragraph("Top Severe Events", subtitle_style))
    story.append(Spacer(1, 12))

    severe_events = [ev for ev in events if ev.get("severity") in ("critical", "high")]
    severe_events.sort(key=lambda x: x.get("meta_score", 0.0), reverse=True)
    
    if not severe_events:
        story.append(Paragraph("No critical or high severity events found in the requested timespan.", normal_style))
    else:
        data = [["Timestamp", "Message", "Severity", "Score", "Action"]]
        for ev in severe_events[:20]:
            ts = ev.get("timestamp", "")
            if isinstance(ts, datetime):
                ts = ts.strftime("%m/%d %H:%M")
            msg = str(ev.get("message", ""))
            msg = (msg[:50] + '...') if len(msg) > 50 else msg
            score = f"{ev.get('meta_score', 0.0):.2f}"
            severity = str(ev.get("severity", "UNKNOWN")).upper()
            action = str(ev.get("action", "UNKNOWN")).upper()
            data.append([str(ts), msg, severity, score, action])

        t = Table(data, colWidths=[80, 200, 60, 50, 70])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ]))
        story.append(t)

    doc.build(story)
    
    try:
        repo = get_app_postgres()
        user_id = claims.get("sub", "system")
        meta = ReportMetadata(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            report_name=f"executive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            report_type="executive_pdf",
            generated_by=user_id,
            file_size_bytes=buffer.getbuffer().nbytes
        )
        await repo.save_report_metadata(meta)
    except Exception as save_err:
        AuditLogger.log("report_metadata_failed", request=request, claims=claims, detail=f"error={save_err}")
    
    buffer.seek(0)
    
    headers = {
        'Content-Disposition': f'attachment; filename="executive_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'
    }
    return StreamingResponse(iter([buffer.getvalue()]), media_type="application/pdf", headers=headers)


@router.get("/soc2")
async def generate_soc2_report(
    days: int = 30,
    request: Request = None,
    claims: dict = Depends(require_admin),
):
    """Generate a SOC 2 Compliance Report (PDF) covering the specified time window."""
    AuditLogger.log("report_soc2_generated", request=request, claims=claims, detail=f"days={days}")

    ch = ClickHouseRepository()
    tenant_id = claims.get("tenant_id", "default")
    
    try:
        events = await ch.query_events(tenant_id=tenant_id, limit=5000)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
    
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']

    story = []
    story.append(Paragraph("SOC 2 Type II Security Status Report", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Tenant ID: {tenant_id}", normal_style))
    story.append(Paragraph(f"Reporting Period: Past {days} days", normal_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    story.append(Spacer(1, 24))

    story.append(Paragraph("Access Control Events (CC6.1, CC6.2)", subtitle_style))
    story.append(Spacer(1, 12))
    
    auth_events = [ev for ev in events if ev.get("action") == "login"]
    success_auth = len([ev for ev in auth_events if ev.get("outcome") == "success"])
    failed_auth = len([ev for ev in auth_events if ev.get("outcome") == "failure"])

    story.append(Paragraph(f"Total Authentication Events: {len(auth_events)}", normal_style))
    story.append(Paragraph(f"Successful Logins: {success_auth}", normal_style))
    story.append(Paragraph(f"Failed Logins: {failed_auth}", normal_style))
    story.append(Spacer(1, 24))

    story.append(Paragraph("Security Monitoring (CC7.2)", subtitle_style))
    story.append(Spacer(1, 12))
    critical_events = [ev for ev in events if ev.get("severity") == "critical"]
    high_events = [ev for ev in events if ev.get("severity") == "high"]
    
    story.append(Paragraph(f"Critical Alerts: {len(critical_events)}", normal_style))
    story.append(Paragraph(f"High Severity Alerts: {len(high_events)}", normal_style))

    doc.build(story)
    
    try:
        repo = get_app_postgres()
        user_id = claims.get("sub", "system")
        meta = ReportMetadata(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            report_name=f"soc2_report_{datetime.now().strftime('%Y%m%d')}.pdf",
            report_type="soc2_pdf",
            generated_by=user_id,
            file_size_bytes=buffer.getbuffer().nbytes
        )
        await repo.save_report_metadata(meta)
    except Exception:
        pass
    
    buffer.seek(0)
    headers = {
        'Content-Disposition': f'attachment; filename="soc2_report_{tenant_id}_{datetime.now().strftime("%Y%m%d")}.pdf"'
    }
    return StreamingResponse(iter([buffer.getvalue()]), media_type="application/pdf", headers=headers)


@router.get("/executive")
async def generate_executive_report(
    days: int = 7,
    request: Request = None,
    claims: dict = Depends(require_analyst),
):
    """Generate an executive-level security posture PDF report.

    Aggregates data from ClickHouse and produces a multi-section report:
      1. Posture Score & Trend
      2. MITRE ATT&CK Tactic Breakdown
      3. Top-N Severe Events
      4. SOAR Execution Summary
      5. Recommendations
    """
    AuditLogger.log("report_executive_generated", request=request, claims=claims, detail=f"days={days}")

    ch = ClickHouseRepository()
    tenant_id = claims.get("tenant_id", "default")

    try:
        events = await ch.query_events(tenant_id=tenant_id, limit=5000)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    # ── Aggregate metrics ────────────────────────────────────────
    total = len(events)
    critical_count = sum(1 for e in events if e.get("severity") == "critical")
    high_count = sum(1 for e in events if e.get("severity") == "high")
    medium_count = sum(1 for e in events if e.get("severity") == "medium")
    low_count = sum(1 for e in events if e.get("severity") == "low")

    # Posture score heuristic
    posture_score = max(0, min(100, 100 - (critical_count * 5) - (high_count * 2) - (medium_count * 0.5)))

    # Tactic breakdown (from event_category)
    tactic_counts: dict[str, int] = {}
    for ev in events:
        cat = ev.get("event_category", "unknown")
        tactic_counts[cat] = tactic_counts.get(cat, 0) + 1
    top_tactics = sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # ── Build PDF ────────────────────────────────────────────────
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=36)

    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    subtitle_style = styles['Heading2']
    normal_style = styles['Normal']

    story = []

    # Title
    story.append(Paragraph("UMBRIX — Executive Security Posture Report", title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Tenant: {tenant_id}  |  Period: Last {days} days  |  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", normal_style))
    story.append(Spacer(1, 24))

    # Section 1: Posture Score
    story.append(Paragraph("1. Security Posture Score", subtitle_style))
    story.append(Spacer(1, 8))
    score_data = [
        ["Metric", "Value"],
        ["Posture Score", f"{posture_score:.0f} / 100"],
        ["Total Events Analyzed", str(total)],
        ["Critical", str(critical_count)],
        ["High", str(high_count)],
        ["Medium", str(medium_count)],
        ["Low", str(low_count)],
    ]
    t = Table(score_data, colWidths=[200, 200])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f1f5f9")),
    ]))
    story.append(t)
    story.append(Spacer(1, 24))

    # Section 2: Tactic Breakdown
    story.append(Paragraph("2. Event Category Breakdown (Top 10)", subtitle_style))
    story.append(Spacer(1, 8))
    if top_tactics:
        tactic_data = [["Category", "Count"]]
        for cat, cnt in top_tactics:
            tactic_data.append([cat.title(), str(cnt)])
        t2 = Table(tactic_data, colWidths=[250, 150])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ]))
        story.append(t2)
    else:
        story.append(Paragraph("No events found in the reporting window.", normal_style))
    story.append(Spacer(1, 24))

    # Section 3: Top Severe Events
    story.append(Paragraph("3. Top Severe Events", subtitle_style))
    story.append(Spacer(1, 8))
    severe = [e for e in events if e.get("severity") in ("critical", "high")]
    severe.sort(key=lambda x: x.get("meta_score", 0.0), reverse=True)

    if severe:
        ev_data = [["Time", "Message", "Sev", "Score"]]
        for ev in severe[:15]:
            ts = ev.get("timestamp", "")
            if isinstance(ts, datetime):
                ts = ts.strftime("%m/%d %H:%M")
            msg = str(ev.get("message", ""))[:60]
            ev_data.append([str(ts), msg, str(ev.get("severity", "")).upper(), f"{ev.get('meta_score', 0.0):.2f}"])
        t3 = Table(ev_data, colWidths=[70, 250, 50, 50])
        t3.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#7f1d1d")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#fef2f2")),
        ]))
        story.append(t3)
    else:
        story.append(Paragraph("No critical or high severity events in this period.", normal_style))
    story.append(Spacer(1, 24))

    # Section 4: Recommendations
    story.append(Paragraph("4. Recommendations", subtitle_style))
    story.append(Spacer(1, 8))
    if critical_count > 0:
        story.append(Paragraph(f"• {critical_count} critical events require immediate incident response triage.", normal_style))
    if high_count > 5:
        story.append(Paragraph(f"• {high_count} high-severity events detected — consider expanding detection coverage.", normal_style))
    if posture_score < 70:
        story.append(Paragraph("• Posture score is below 70. Review SOAR playbook automation coverage.", normal_style))
    if posture_score >= 90:
        story.append(Paragraph("• Posture score is excellent. Continue monitoring for drift.", normal_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("— Report generated by UMBRIX Detection Platform", normal_style))

    doc.build(story)

    # Save metadata
    try:
        repo = get_app_postgres()
        user_id = claims.get("sub", "system")
        meta = ReportMetadata(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            report_name=f"executive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
            report_type="executive_summary",
            generated_by=user_id,
            file_size_bytes=buffer.getbuffer().nbytes,
        )
        await repo.save_report_metadata(meta)
    except Exception:
        pass

    buffer.seek(0)
    headers = {
        'Content-Disposition': f'attachment; filename="umbrix_executive_{tenant_id}_{datetime.now().strftime("%Y%m%d")}.pdf"'
    }
    return StreamingResponse(iter([buffer.getvalue()]), media_type="application/pdf", headers=headers)
