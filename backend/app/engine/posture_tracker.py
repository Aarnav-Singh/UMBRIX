"""Posture Tracker — Tracks organization-level security posture.

Generates snapshots and fires threshold alerts.
"""
from __future__ import annotations
import structlog
from app.dependencies import get_app_clickhouse, get_app_redis, get_app_broadcaster

logger = structlog.get_logger(__name__)


class PostureTracker:
    """Calculates and snapshots organization posture."""

    @classmethod
    async def compute_snapshot(cls, tenant_id: str) -> float:
        """Compute the current posture score for a tenant (0.0 to 100.0)."""
        ch = get_app_clickhouse()
        score = 100.0
        
        # 1. Deduct points for active campaigns
        campaigns_query = f"""
            SELECT count() as active_count, avg(severity) as avg_sev
            FROM campaigns
            WHERE tenant_id = '{tenant_id}' AND status = 'active'
        """
        try:
            res = await ch.client.fetch(campaigns_query)
            if res:
                active_count = res[0].get("active_count", 0)
                avg_sev = res[0].get("avg_sev", 0.0)
                score -= (active_count * 2.0)
                score -= (avg_sev * 5.0)
        except Exception as e:
            logger.debug("posture_campaign_query_failed", detail=str(e))
            
        # 2. Deduct points for recent vulnerable assets/findings
        vuln_query = f"""
            SELECT count() as vuln_count
            FROM events
            WHERE tenant_id = '{tenant_id}' AND action = 'vulnerability_found'
              AND timestamp >= now() - INTERVAL 7 DAY
        """
        try:
            res = await ch.client.fetch(vuln_query)
            if res:
                vuln_count = res[0].get("vuln_count", 0)
                score -= (vuln_count * 0.5)
        except Exception:
            pass

        final_score = max(0.0, min(100.0, score))
        
        # Snapshot in Redis and check threshold
        try:
            redis = get_app_redis()
            key = f"posture:{tenant_id}:current"
            prev_score_str = await redis.get(key)
            await redis.set(key, str(final_score))
            
            if prev_score_str:
                prev_score = float(prev_score_str)
                # Fire an alert if dropping below 70 from out of 70
                if prev_score > 70.0 and final_score <= 70.0:
                    logger.warning("posture_dropped_below_threshold", tenant_id=tenant_id, score=final_score)
                    broadcaster = get_app_broadcaster()
                    await broadcaster.broadcast_to_tenant(
                        tenant_id,
                        {
                            "type": "posture_alert", 
                            "message": f"Security Posture dropped to {final_score:.1f}"
                        }
                    )
        except Exception as e:
            logger.debug("posture_snapshot_failed", detail=str(e))
            
        return final_score
