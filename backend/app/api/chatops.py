"""ChatOps API for Bi-Directional Bot Integrations (Slack/Teams).

Receives interactive webhook callbacks (e.g., when an analyst clicks "Approve" 
on a Slack Actionable Message) and triggers SOAR execution resumption.
"""
from __future__ import annotations

import hmac
import hashlib
import time
from fastapi import APIRouter, HTTPException, Request

import structlog
from app.config import settings
from app.dependencies import get_app_engine, get_app_postgres
from app.services.soar.engine import Playbook, Node

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/chatops", tags=["chatops"])


def verify_slack_signature(request: Request, raw_body: bytes) -> bool:
    """Verify Slack incoming webhook signature for security."""
    slack_signing_secret = getattr(settings, "slack_signing_secret", None)
    if not slack_signing_secret:
        # If not configured, bypass for local dev, but warn
        logger.warning("slack_signing_secret_missing_bypassing_auth")
        return True
        
    slack_signature = request.headers.get("X-Slack-Signature", "")
    slack_request_timestamp = request.headers.get("X-Slack-Request-Timestamp", "0")
    
    # Check for replay attacks (5 minute tolerance)
    if abs(time.time() - int(slack_request_timestamp)) > 60 * 5:
        return False
        
    sig_basestring = f"v0:{slack_request_timestamp}:{raw_body.decode('utf-8')}"
    my_signature = "v0=" + hmac.new(
        slack_signing_secret.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(my_signature, slack_signature)


async def _resume_soar_from_chatops(playbook_id: str, approval_id: str, decision: str, platform: str) -> dict:
    """Shared logic for both Slack and Teams handlers to resume a SOAR playbook."""
    engine = get_app_engine()
    postgres = get_app_postgres()

    paused = await postgres.get_paused_state(approval_id)
    if not paused:
        logger.warning("chatops_approval_not_found", approval_id=approval_id, platform=platform)
        return {"status": "error", "message": f"No paused playbook for approval_id={approval_id}"}

    playbook_model = await postgres.get_playbook(paused.playbook_id)
    if not playbook_model:
        logger.error("chatops_playbook_not_found", playbook_id=paused.playbook_id, platform=platform)
        return {"status": "error", "message": f"Playbook {paused.playbook_id} not found"}

    # Convert to domain model
    nodes = [
        Node(
            id=n.get("id", "unknown"),
            action_type=n.get("action_type", ""),
            provider=n.get("provider", "unknown"),
            params=n.get("params", {})
        )
        for n in playbook_model.nodes
    ]
    playbook = Playbook(id=playbook_model.id, name=playbook_model.name, nodes=nodes)

    action = "approve" if decision in ("approve", "approved") else "reject"
    result = await engine.resume_playbook(playbook, paused.paused_node_index, action)
    await postgres.clear_paused_state(approval_id)

    logger.info(
        "chatops_soar_resumed",
        platform=platform,
        playbook=playbook_id,
        approval=approval_id,
        decision=action,
        result_count=len(result),
    )
    return {"status": "success", "message": f"Playbook resumed via {platform}: {action}", "results": result}


@router.post("/webhook/slack")
async def slack_interactive_webhook(request: Request):
    """Receive Slack block kit interactions (e.g., Button Clicks)."""
    raw_body = await request.body()
    
    if not verify_slack_signature(request, raw_body):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")
        
    form_data = await request.form()
    payload_str = form_data.get("payload")
    if not payload_str:
        return {"status": "ignored", "reason": "No payload"}
        
    import json
    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Only process block_actions (button clicks)
    if payload.get("type") != "block_actions":
        return {"status": "ignored", "reason": "Not a block action"}

    actions = payload.get("actions", [])
    if not actions:
        return {"status": "ignored", "reason": "No actions found"}

    action = actions[0]
    action_id = action.get("action_id")
    value = action.get("value", "")  # Expected format: "playbook_id:approval_id:decision"

    parts = value.split(":")
    if len(parts) == 3 and action_id in ("soar_approve", "soar_reject"):
        playbook_id, approval_id, decision = parts
        return await _resume_soar_from_chatops(playbook_id, approval_id, decision, "slack")
        
    return {"status": "ignored", "reason": "Unknown action"}


@router.post("/webhook/teams")
async def teams_interactive_webhook(request: Request):
    """Receive Microsoft Teams actionable message responses."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Extract decision from Adaptive Card Submit Action
    decision = payload.get("action", "unknown")
    context = payload.get("context", {})
    playbook_id = context.get("playbook_id")
    approval_id = context.get("approval_id")

    if playbook_id and approval_id:
        return await _resume_soar_from_chatops(playbook_id, approval_id, decision, "teams")

    return {"status": "ignored", "reason": "Missing SOAR context"}
