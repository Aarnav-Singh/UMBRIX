"""Health check API.

GET /api/v1/health returns the status of all dependencies.
"""
from __future__ import annotations

from fastapi import APIRouter
from typing import Any

from app.dependencies import get_app_clickhouse, get_app_redis

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check() -> dict:
    checks: dict[str, str] = {}

    # ClickHouse
    try:
        ch = get_app_clickhouse()
        count = await ch.get_event_count()
        checks["clickhouse"] = f"ok ({count} events)"
    except Exception as exc:
        checks["clickhouse"] = f"error: {exc}"

    # Redis
    try:
        redis = get_app_redis()
        await redis.client.ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"

    all_ok = all(v.startswith("ok") for v in checks.values())
    return {
        "status": "healthy" if all_ok else "degraded",
        "checks": checks,
    }

@router.get("/health/deep")
async def health_deep() -> dict:
    """Deep health check for Observability Dashboard."""
    from app.dependencies import get_app_clickhouse, get_app_redis, get_app_qdrant
    import time

    checks: dict[str, Any] = {}
    status = "healthy"

    # ClickHouse
    try:
        ch = get_app_clickhouse()
        t0 = time.time()
        count = await ch.get_event_count()
        latency_ms = round((time.time() - t0) * 1000, 2)
        checks["clickhouse"] = {"status": "ok", "event_count": count, "latency_ms": latency_ms}
    except Exception as exc:
        checks["clickhouse"] = {"status": "error", "message": str(exc)}
        status = "degraded"

    # Redis
    try:
        redis = get_app_redis()
        t0 = time.time()
        await redis.client.ping()
        latency_ms = round((time.time() - t0) * 1000, 2)
        checks["redis"] = {"status": "ok", "latency_ms": latency_ms}
    except Exception as exc:
        checks["redis"] = {"status": "error", "message": str(exc)}
        status = "degraded"

    # Qdrant
    try:
        qdrant = get_app_qdrant()
        if getattr(qdrant, "_client", None):
            t0 = time.time()
            col_info = qdrant.client.get_collection("behavioral_dna")
            latency_ms = round((time.time() - t0) * 1000, 2)
            vector_count = col_info.points_count
            checks["qdrant"] = {"status": "ok", "vector_count": vector_count, "latency_ms": latency_ms}
        else:
            checks["qdrant"] = {"status": "disabled", "message": "Client not initialized"}
    except Exception as exc:
        checks["qdrant"] = {"status": "error", "message": str(exc)}
        status = "degraded"

    return {
        "status": status,
        "components": checks,
    }
