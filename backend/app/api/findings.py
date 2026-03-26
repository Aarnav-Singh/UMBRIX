"""Findings API — actionable intelligence derived from live event data."""
from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from app.dependencies import get_app_clickhouse, get_app_redis, get_app_postgres, get_app_pipeline
from app.middleware.auth import require_analyst, AuditLogger
from app.repositories.postgres import AnalystVerdict
import uuid
from datetime import datetime

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])
logger = structlog.get_logger(__name__)


class ActionRequest(BaseModel):
    action: str  # "approve" | "dismiss" | "modify"
    comment: str | None = None
    stream_scores: list[float] | None = None


@router.get("")
async def list_findings(
    limit: int = Query(20, ge=1, le=100),
    min_severity: str = Query("medium"),
    claims: dict = Depends(require_analyst),
):
    """Generate findings from high-severity events and active campaigns. Requires analyst role."""
    ch = get_app_clickhouse()
    redis = get_app_redis()

    findings: list[dict] = []
    severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_sev_val = severity_map.get(min_severity, 2)

    # 1. Pull high-scoring events from ClickHouse
    try:
        events, _ = await ch.query_events_paginated(
            limit=limit,
            min_score=0.5,
        )
        for ev in events:
            sev = ev.get("severity", "info")
            if severity_map.get(sev, 0) < min_sev_val:
                continue
            findings.append({
                "id": f"FE-{ev.get('event_id', 'unknown')[:8]}",
                "source": "campaign" if ev.get("campaign_id") else "detection",
                "title": ev.get("message") or f"High-risk event from {ev.get('source_type', 'unknown')}",
                "description": (
                    f"ML meta-score {ev.get('meta_score', 0):.2f} — "
                    f"source {ev.get('src_ip', 'N/A')} → {ev.get('dst_ip', 'N/A')}:{ev.get('dst_port', 'N/A')}"
                ),
                "severity": sev,
                "linked_campaign": ev.get("campaign_id"),
                "meta_score": ev.get("meta_score", 0),
                "status": "open",
                "created_at": str(ev.get("timestamp", "")),
            })
    except Exception as exc:
        logger.error("findings_ch_query_failed", error=str(exc))

    # 2. Enrich with campaign data from Redis
    try:
        campaigns = await redis.get_all_campaigns("default")
        for cmeta in campaigns:
            cid = cmeta.get("id", "unknown")
            findings.append({
                "id": f"FC-{cid[:8]}",
                "source": "campaign",
                "title": f"Active campaign: {cid}",
                "description": f"Stage: {cmeta.get('stage', 'unknown')}, affected assets: {cmeta.get('affected_assets', 0)}",
                "severity": cmeta.get("severity", "high"),
                "linked_campaign": cid,
                "meta_score": cmeta.get("meta_score", 0),
                "status": "open",
                "created_at": cmeta.get("created_at", ""),
            })
    except Exception as exc:
        logger.debug("findings_campaign_enrichment_unavailable", error=str(exc))

    # Sort by severity, then meta_score
    findings.sort(
        key=lambda f: (severity_map.get(f.get("severity", "info"), 0), f.get("meta_score", 0)),
        reverse=True,
    )

    return {"findings": findings[:limit], "total": len(findings)}


@router.post("/{finding_id}/action")
async def action_finding(
    finding_id: str,
    body: ActionRequest,
    request: Request,
    claims: dict = Depends(require_analyst),
):
    """Record analyst approve/dismiss/modify decision. Requires analyst role."""
    redis = get_app_redis()
    postgres = get_app_postgres()
    analyst_id = claims.get("sub", "unknown")

    AuditLogger.log(
        "finding_action",
        request=request,
        claims=claims,
        target=finding_id,
        detail=f"action={body.action}",
    )

    try:
        await redis.cache_set(
            f"finding_action:{finding_id}",
            str({"action": body.action, "comment": body.comment}),
            ttl=86400 * 30,
        )
    except Exception as exc:
        logger.warning("finding_action_store_failed", error=str(exc))

    try:
        verdict = AnalystVerdict(
            id=str(uuid.uuid4()),
            tenant_id=claims.get("tenant_id", "default"),
            event_id=finding_id,
            analyst_id=analyst_id,
            decision=body.action,
            comment=body.comment,
            created_at=datetime.utcnow()
        )
        await postgres.save_verdict(verdict)
    except Exception as exc:
        logger.error("postgres_verdict_save_failed", error=str(exc))

    pipeline = get_app_pipeline()
    ml_verdict = "true_positive" if body.action == "approve" else "false_positive" if body.action == "dismiss" else "unknown"
    if ml_verdict != "unknown":
        scores_to_use = body.stream_scores or [0.5, 0.5, 0.5, 0.5, 0.5]
        try:
            pipeline.meta_learner.update_weights(ml_verdict, scores_to_use)
            # Persist updated weights to PostgreSQL (Phase 22B)
            await pipeline.meta_learner.persist_weights(
                tenant_id=claims.get("tenant_id", "default")
            )
            logger.info("meta_learner_weights_tuned", finding_id=finding_id, verdict=ml_verdict)
        except Exception as exc:
            logger.error("meta_learner_tuning_failed", error=str(exc))

    return {
        "finding_id": finding_id,
        "action": body.action,
        "status": "acknowledged" if body.action == "approve" else "dismissed",
        "feedback_recorded": True,
        "new_weights": pipeline.meta_learner.current_weights if hasattr(pipeline, "meta_learner") else []
    }

