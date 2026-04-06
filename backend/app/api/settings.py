import json
from pydantic import BaseModel
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request

from app.middleware.auth import require_analyst, require_admin, AuditLogger
from app.repositories.redis_store import RedisStore

router = APIRouter(prefix="/settings", tags=["Settings"])

class AlertConfig(BaseModel):
    slack_webhook_url: Optional[str] = None
    generic_webhook_url: Optional[str] = None

@router.get("/alerting", response_model=AlertConfig)
async def get_alerting_config(claims: dict = Depends(require_analyst)):
    """Get current alerting configuration for the tenant. Requires analyst role."""
    redis = RedisStore()
    tenant_id = claims.get("tenant_id", "default")
    try:
        raw = await redis.get(f"alert_config:{tenant_id}")
        if raw:
            return AlertConfig(**json.loads(raw))
        return AlertConfig()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/alerting", response_model=AlertConfig)
async def update_alerting_config(
    config: AlertConfig,
    request: Request,
    claims: dict = Depends(require_admin),
):
    """Update alerting configuration for the tenant. Admin only."""
    redis = RedisStore()
    tenant_id = claims.get("tenant_id", "default")
    AuditLogger.log("alerting_config_updated", request=request, claims=claims, detail=f"tenant={tenant_id}")
    try:
        # Save to redis
        await redis.set(f"alert_config:{tenant_id}", json.dumps(config.model_dump()))
        return config
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

