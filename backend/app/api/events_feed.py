"""Events Feed API — paginated recent events from ClickHouse."""
from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, Query

from app.dependencies import get_app_clickhouse
from app.middleware.auth import require_viewer

router = APIRouter(prefix="/api/v1/events", tags=["events"])
logger = structlog.get_logger(__name__)


@router.get("/recent")
async def recent_events(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    campaign_id: str | None = Query(None),
    source_type: str | None = Query(None),
    claims: dict = Depends(require_viewer),
):
    """Paginated recent events with filtering — live from ClickHouse."""
    ch = get_app_clickhouse()
    tenant_id = claims.get("tenant_id", "default")
    try:
        events, total = await ch.query_events_paginated(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            min_score=min_score,
            campaign_id=campaign_id,
            source_type=source_type,
        )
    except Exception as exc:
        logger.error("events_feed_query_failed", error=str(exc))
        events, total = [], 0

    return {
        "events": events,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
