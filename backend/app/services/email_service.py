"""Email Notification Service — SMTP-based delivery.

Uses ``aiosmtplib`` for async email sending.  Configuration is read from
``settings.smtp_*`` fields, which work with any SMTP provider including
AWS SES, SendGrid, and generic SMTP relays.
"""
from __future__ import annotations

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

import structlog

from app.config import settings

logger = structlog.get_logger(__name__)


class EmailService:
    """Async SMTP email sender."""

    def __init__(self) -> None:
        self._configured = bool(settings.smtp_host and settings.smtp_user)

    @property
    def is_configured(self) -> bool:
        return self._configured

    async def send_email(
        self,
        to: str | list[str],
        subject: str,
        body_html: str,
        body_text: Optional[str] = None,
        from_address: Optional[str] = None,
    ) -> bool:
        """Send an email message.

        Returns ``True`` on success, ``False`` on failure (never raises).
        """
        if not self._configured:
            logger.warning("email_not_configured_skipping")
            return False

        recipients = [to] if isinstance(to, str) else to
        sender = from_address or settings.smtp_from_address

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)

        if body_text:
            msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))

        try:
            import aiosmtplib

            await aiosmtplib.send(
                msg,
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_user,
                password=settings.smtp_password,
                use_tls=settings.smtp_use_tls,
                timeout=15,
            )
            logger.info("email_sent", to=recipients, subject=subject)
            return True
        except ImportError:
            logger.error("aiosmtplib_not_installed")
            return False
        except Exception as exc:
            logger.error("email_send_failed", error=str(exc), to=recipients)
            return False

    async def send_alert(
        self,
        to: str | list[str],
        finding_title: str,
        severity: str,
        details: str,
    ) -> bool:
        """Send a security alert email with a pre-built HTML template."""
        sev_color = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#3b82f6",
            "info": "#64748b",
        }.get(severity.lower(), "#64748b")

        html = f"""
        <div style="font-family: -apple-system, sans-serif; max-width: 600px; margin: auto;">
            <div style="background: #0f172a; padding: 24px; border-radius: 12px;">
                <h2 style="color: #e2e8f0; margin: 0 0 8px;">
                    🔒 UMBRIX Alert
                </h2>
                <div style="background: {sev_color}22; border-left: 4px solid {sev_color};
                            padding: 12px 16px; border-radius: 8px; margin: 16px 0;">
                    <span style="color: {sev_color}; font-weight: 700; text-transform: uppercase;
                                 font-size: 12px;">{severity}</span>
                    <h3 style="color: #f1f5f9; margin: 4px 0 0;">{finding_title}</h3>
                </div>
                <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">{details}</p>
                <p style="color: #475569; font-size: 12px; margin-top: 24px;">
                    — UMBRIX V2 Automated Alert
                </p>
            </div>
        </div>
        """
        return await self.send_email(
            to=to,
            subject=f"[{severity.upper()}] {finding_title}",
            body_html=html,
            body_text=f"[{severity.upper()}] {finding_title}\n\n{details}",
        )

    async def send_digest(
        self,
        to: str | list[str],
        subject: str,
        html_content: str,
    ) -> bool:
        """Send a compliance/executive digest email."""
        return await self.send_email(to=to, subject=subject, body_html=html_content)

    async def send_report(
        self,
        to: str | list[str],
        report_name: str,
        report_type: str,
        download_url: str | None = None,
    ) -> bool:
        """Send a report-generated notification email."""
        html = f"""
        <div style="font-family: -apple-system, sans-serif; max-width: 600px; margin: auto;">
            <div style="background: #0f172a; padding: 24px; border-radius: 12px;">
                <h2 style="color: #e2e8f0; margin: 0 0 8px;">
                    📊 Report Ready
                </h2>
                <div style="background: #1e293b; padding: 16px; border-radius: 8px; margin: 16px 0;">
                    <p style="color: #94a3b8; font-size: 12px; margin: 0 0 4px;">Report</p>
                    <p style="color: #f1f5f9; font-size: 16px; font-weight: 700; margin: 0;">
                        {report_name}
                    </p>
                    <p style="color: #64748b; font-size: 11px; margin: 8px 0 0;">
                        Type: {report_type}
                    </p>
                </div>
                {f'<a href="{download_url}" style="display:inline-block; background:#22d3ee; color:#0f172a; padding:10px 20px; border-radius:6px; text-decoration:none; font-weight:700; font-size:13px;">Download Report</a>' if download_url else ''}
                <p style="color: #475569; font-size: 12px; margin-top: 24px;">
                    — UMBRIX V2 Reporting Engine
                </p>
            </div>
        </div>
        """
        return await self.send_email(
            to=to,
            subject=f"Report Ready: {report_name}",
            body_html=html,
            body_text=f"Report Ready: {report_name} ({report_type})",
        )


# Module-level singleton
email_service = EmailService()
