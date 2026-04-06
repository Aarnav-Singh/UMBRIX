"""Asset Inventory — Dynamic Asset Tracking and Risk Weighting.

Maintains a view of critical assets per tenant. Uses Redis for fast
lookups of dynamic criticality and Postgres as the persistence store.
"""
from __future__ import annotations
import structlog
from app.dependencies import get_app_redis

logger = structlog.get_logger(__name__)


class AssetInventory:
    """Tracks asset properties and dynamic criticality."""

    @classmethod
    async def get_criticality(cls, tenant_id: str, asset_ref: str) -> float:
        """Fetch the criticality of an asset (0.0 to 1.0).
        
        Queries Redis first. On miss, queries ServiceNow CMDB if configured.
        Falls back to PostgreSQL local registry if CMDB fails or is not configured.
        """
        redis = get_app_redis()
        cache_key = f"asset_crit:{tenant_id}:{asset_ref}"
        
        try:
            cached = await redis.get(cache_key)
            if cached is not None:
                return float(cached)
        except Exception as e:
            logger.debug("redis_criticality_fetch_error", error=str(e))
        
        criticality = 0.5
        found = False
        
        from app.config import settings
        if settings.servicenow_instance and settings.servicenow_user and settings.servicenow_password:
            import httpx
            url = f"{settings.servicenow_instance.rstrip('/')}/api/now/table/cmdb_ci"
            try:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.get(
                        url,
                        params={"sysparm_query": f"name={asset_ref}", "sysparm_limit": 1},
                        auth=(settings.servicenow_user, settings.servicenow_password)
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("result", [])
                        if data:
                            ci = data[0]
                            bus_crit = ci.get("business_criticality", "3")
                            try:
                                val = int(bus_crit)
                                if val == 1:
                                    criticality = 0.9
                                elif val == 2:
                                    criticality = 0.7
                                elif val == 3:
                                    criticality = 0.5
                                else:
                                    criticality = 0.3
                                found = True
                            except ValueError:
                                pass
            except Exception as e:
                logger.warning("servicenow_query_failed", asset=asset_ref, error=str(e))
                
        if not found:
            from app.dependencies import get_app_postgres
            from sqlalchemy import text
            try:
                db = get_app_postgres()
                async with db._session() as session:
                    result = await session.execute(
                        text("SELECT criticality_score FROM registered_assets WHERE tenant_id = :tid AND asset_name = :n"),
                        {"tid": tenant_id, "n": asset_ref}
                    )
                    row = result.scalar_one_or_none()
                    if row is not None:
                        criticality = float(row)
            except Exception as e:
                logger.warning("postgres_criticality_fetch_failed", error=str(e))
        
        try:
            await redis.set(cache_key, str(criticality), expire_sec=3600)
        except Exception:
            pass
            
        return criticality

    @classmethod
    async def set_criticality(cls, tenant_id: str, asset_ref: str, criticality: float) -> None:
        """Update the criticality of an asset explicitly in cache."""
        redis = get_app_redis()
        cache_key = f"asset_crit:{tenant_id}:{asset_ref}"
        try:
            await redis.set(cache_key, str(criticality), expire_sec=86400)
            logger.info("asset_criticality_updated", tenant_id=tenant_id, asset=asset_ref, score=criticality)
        except Exception as e:
            logger.error("asset_criticality_set_failed", error=str(e))
