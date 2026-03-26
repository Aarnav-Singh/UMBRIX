"""SOAR Notification Providers — Teams & Slack.

Provides outgoing webhook messages for automated pipeline decisions.
"""
import httpx
import structlog
from typing import Any

from app.services.soar.actions import ActionProvider, ActionExecutionError
from app.config import settings

logger = structlog.get_logger(__name__)


class SlackActionProvider(ActionProvider):
    """Sends notifications to a Slack channel via Webhook or Bot Token."""

    @property
    def id(self) -> str:
        return "slack"

    @property
    def supported_actions(self) -> list[str]:
        return ["send_notification"]

    async def execute(self, action: str, context: dict[str, Any]) -> dict[str, Any]:
        if action != "send_notification":
            raise ActionExecutionError(f"Unsupported action: {action}")

        # Webhook URL is heavily preferred for SOAR alerts
        webhook_url = context.get("webhook_url") or settings.slack_webhook_url
        if not webhook_url:
            raise ActionExecutionError("No slack_webhook_url configured in context or settings.")

        message = context.get("message", "Sentinel Fabric Alert")
        event_id = context.get("event_id", "Unknown")
        severity = context.get("severity", "info")

        payload = {
            "text": f"*[{severity.upper()}] Sentinel Fabric Alert:*\n{message}\nEvent ID: `{event_id}`"
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=payload, timeout=10.0)
            if resp.status_code >= 400:
                raise ActionExecutionError(f"Slack API error: {resp.status_code} - {resp.text}")

        return {
            "status": "success",
            "provider": "slack",
            "action": "send_notification"
        }


class TeamsActionProvider(ActionProvider):
    """Sends adaptive cards to Microsoft Teams via Incoming Webhook."""

    @property
    def id(self) -> str:
        return "teams"

    @property
    def supported_actions(self) -> list[str]:
        return ["send_notification"]

    async def execute(self, action: str, context: dict[str, Any]) -> dict[str, Any]:
        if action != "send_notification":
            raise ActionExecutionError(f"Unsupported action: {action}")

        webhook_url = context.get("webhook_url") or settings.teams_webhook_url
        if not webhook_url:
            raise ActionExecutionError("No teams_webhook_url configured in context or settings.")

        message = context.get("message", "Sentinel Fabric Alert")
        event_id = context.get("event_id", "Unknown")
        severity = context.get("severity", "info")

        # Basic Adaptive Card format for Teams
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "body": [
                            {
                                "type": "TextBlock",
                                "size": "Medium",
                                "weight": "Bolder",
                                "text": f"Sentinel Fabric V2: {severity.upper()} Alert"
                            },
                            {
                                "type": "TextBlock",
                                "text": message,
                                "wrap": True
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Event ID", "value": event_id}
                                ]
                            }
                        ],
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.4"
                    }
                }
            ]
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(webhook_url, json=payload, timeout=10.0)
            if resp.status_code >= 400:
                raise ActionExecutionError(f"Teams API error: {resp.status_code} - {resp.text}")

        return {
            "status": "success",
            "provider": "teams",
            "action": "send_notification"
        }
