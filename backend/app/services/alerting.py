"""Active Alerting & Webhooks Engine.

Handles dispatching high-severity alerts to external integrations
(like Slack, Jira, or generic webhooks).
"""
import httpx
import structlog
import json

from app.schemas.canonical_event import CanonicalEvent

logger = structlog.get_logger(__name__)


class AlertingEngine:
    """Dispatches alerts to configured integrations."""

    def __init__(self, redis_client) -> None:
        # Expected to be an instance of our RedisStore wrapper or raw redis
        self._redis = redis_client

    async def get_config(self, tenant_id: str) -> dict:
        """Fetch alert configuration for a given tenant from Redis."""
        # Simple string lookup, depending on redis.get signature
        try:
            # Our custom RedisStore typically uses `get` but let's be safe
            raw = None
            if hasattr(self._redis, "get"):
                raw = await self._redis.get(f"alert_config:{tenant_id}")
            elif hasattr(self._redis, "_redis") and self._redis._redis:
                raw = await self._redis._redis.get(f"alert_config:{tenant_id}")
            
            if raw:
                return json.loads(raw)
        except Exception as e:
            logger.warning("failed_to_load_alert_config", error=str(e))
        return {}

    async def dispatch(self, event: CanonicalEvent) -> None:
        """Evaluate event and dispatch if conditions are met.
        
        Typically dispatches if meta_score > 0.8 OR critical severity.
        """
        score = 0.0
        if event.ml_scores and event.ml_scores.meta_score is not None:
            score = event.ml_scores.meta_score
            
        is_critical = event.severity and event.severity.value in ["high", "critical"]
        
        # Only alert for significant findings (>0.85 or explicit critical severity)
        if score < 0.85 and not is_critical:
            return

        config = await self.get_config(event.metadata.tenant_id)
        
        # Dispatch to Slack
        slack_webhook = config.get("slack_webhook_url")
        if slack_webhook:
            await self._send_slack(slack_webhook, event, score)

        # Dispatch to Discord
        discord_webhook = config.get("discord_webhook_url")
        if discord_webhook:
            await self._send_discord(discord_webhook, event, score)

        # Dispatch to Teams
        teams_webhook = config.get("teams_webhook_url")
        if teams_webhook:
            await self._send_teams(teams_webhook, event, score)

        # Dispatch to Generic Webhook
        generic_webhook = config.get("generic_webhook_url")
        if generic_webhook:
            await self._send_generic(generic_webhook, event)

    async def _send_slack(self, webhook_url: str, event: CanonicalEvent, score: float) -> None:
        """Send an alert payload formatted for Slack."""
        color = "#ff0000" if score > 0.9 else "#ff9900"
        payload = {
            "attachments": [
                {
                    "fallback": f"Security Alert: {event.event_id}",
                    "color": color,
                    "title": f"New High-Severity Alert! Score: {score:.2f}",
                    "text": event.message or "Suspicious activity detected.",
                    "fields": [
                        {"title": "Event ID", "value": event.event_id, "short": True},
                        {"title": "Source Type", "value": event.source_type, "short": True},
                    ]
                }
            ]
        }
        
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(webhook_url, json=payload, timeout=5.0)
                resp.raise_for_status()
                logger.info("slack_alert_sent", event_id=event.event_id)
        except Exception as e:
            logger.error("slack_alert_failed", error=str(e), event_id=event.event_id)

    async def _send_generic(self, webhook_url: str, event: CanonicalEvent) -> None:
        """Send raw CanonicalEvent JSON to a generic webhook endpoint."""
        payload = event.model_dump(mode="json")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(webhook_url, json=payload, timeout=5.0)
                resp.raise_for_status()
                logger.info("generic_webhook_sent", event_id=event.event_id)
        except Exception as e:
            logger.error("generic_webhook_failed", error=str(e), event_id=event.event_id)

    async def _send_discord(self, webhook_url: str, event: CanonicalEvent, score: float) -> None:
        """Send an alert payload formatted for Discord."""
        color = 16711680 if score > 0.9 else 16750848 # Red or Orange
        payload = {
            "embeds": [{
                "title": f"New High-Severity Alert! Score: {score:.2f}",
                "description": event.message or "Suspicious activity detected.",
                "color": color,
                "fields": [
                    {"name": "Event ID", "value": event.event_id, "inline": True},
                    {"name": "Source Type", "value": event.source_type, "inline": True},
                ]
            }]
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(webhook_url, json=payload, timeout=5.0)
                resp.raise_for_status()
                logger.info("discord_alert_sent", event_id=event.event_id)
        except Exception as e:
            logger.error("discord_alert_failed", error=str(e), event_id=event.event_id)

    async def _send_teams(self, webhook_url: str, event: CanonicalEvent, score: float) -> None:
        """Send an alert payload formatted for MS Teams (Adaptive Card)."""
        color = "Attention" if score > 0.9 else "Warning"
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.2",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": f"Security Alert: Score {score:.2f}",
                                "weight": "Bolder",
                                "size": "Medium",
                                "color": color
                            },
                            {
                                "type": "TextBlock",
                                "text": event.message or "Suspicious activity detected.",
                                "wrap": True
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Event ID", "value": event.event_id},
                                    {"title": "Source Type", "value": event.source_type}
                                ]
                            }
                        ]
                    }
                }
            ]
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(webhook_url, json=payload, timeout=5.0)
                resp.raise_for_status()
                logger.info("teams_alert_sent", event_id=event.event_id)
        except Exception as e:
            logger.error("teams_alert_failed", error=str(e), event_id=event.event_id)

