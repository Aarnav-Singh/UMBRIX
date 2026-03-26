"""Asset Management API — CMDB registration and criticality management.

Provides REST endpoints for seeding the local PostgreSQL asset registry
which serves as a fallback for ServiceNow CMDB lookups.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.dependencies import get_app_postgres
from app.middleware.auth import require_admin

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["assets"])


class AssetRegistrationRequest(BaseModel):
    asset_name: str = Field(..., min_length=1, max_length=256)
    criticality_score: float = Field(..., ge=0.0, le=1.0)


class AssetRegistrationResponse(BaseModel):
    status: str
    asset: str
    criticality: float


@router.post("/assets/register", response_model=AssetRegistrationResponse)
async def register_asset(
    req: AssetRegistrationRequest,
    claims: dict = Depends(require_admin),
):
    """Seed or update an asset in the local PostgreSQL fallback registry.

    Admin-gated. Used when ServiceNow CMDB is unavailable or for
    manually overriding criticality scores.
    """
    from app.repositories.postgres import RegisteredAsset
    from sqlalchemy import select
    from sqlalchemy.exc import IntegrityError

    tenant_id = claims.get("tenant_id", "default")
    db = get_app_postgres()

    # Try insert, fallback to update on conflict
    try:
        async with db._session() as session:
            asset = RegisteredAsset(
                tenant_id=tenant_id,
                asset_name=req.asset_name,
                criticality_score=req.criticality_score,
            )
            session.add(asset)
            await session.commit()
            logger.info("asset_registered", tenant=tenant_id, asset=req.asset_name)
    except IntegrityError:
        async with db._session() as session:
            result = await session.execute(
                select(RegisteredAsset).where(
                    RegisteredAsset.tenant_id == tenant_id,
                    RegisteredAsset.asset_name == req.asset_name,
                )
            )
            existing = result.scalar_one_or_none()
            if existing:
                existing.criticality_score = req.criticality_score
                await session.commit()
                logger.info("asset_criticality_updated", tenant=tenant_id, asset=req.asset_name)

    # Also update the Redis cache immediately
    from app.engine.asset_inventory import AssetInventory
    await AssetInventory.set_criticality(tenant_id, req.asset_name, req.criticality_score)

    return AssetRegistrationResponse(
        status="registered",
        asset=req.asset_name,
        criticality=req.criticality_score,
    )
