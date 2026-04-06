"""Campaigns API — CRUD and investigation endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.dependencies import get_app_redis
from app.middleware.auth import require_viewer

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


@router.get("/")
async def list_campaigns(claims: dict = Depends(require_viewer)) -> list[dict]:
    """Return active campaigns. Requires viewer role."""
    redis = get_app_redis()
    return await redis.get_all_campaigns("default")


@router.get("/{campaign_id}")
async def get_campaign(campaign_id: str, claims: dict = Depends(require_viewer)) -> dict:
    """Get campaign details. Requires viewer role."""
    redis = get_app_redis()
    meta = await redis.cache_get(f"campaign_meta:default:{campaign_id}")
    if meta:
        return {"id": campaign_id, "meta": meta}
    return {"id": campaign_id, "status": "not_found"}
