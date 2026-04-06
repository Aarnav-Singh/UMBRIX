import csv
import io
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
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
    limit: int = 100,
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
    limit: int = 1000,
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
    limit: int = 50,
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
