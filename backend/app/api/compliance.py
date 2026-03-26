"""Compliance API — SOC 2 Type II audit trail and status endpoints.

Provides:
  GET /api/v1/compliance/status       — SOC 2 compliance health report
  GET /api/v1/compliance/audit-trail  — Query immutable audit logs (admin-only)
  POST /api/v1/compliance/retention   — Trigger retention purge (admin-only)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.middleware.auth import require_auth, require_admin
from app.dependencies import get_app_postgres
from app.services.compliance import ComplianceService

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/compliance", tags=["compliance"])


def _get_compliance_service():
    """Build ComplianceService from the running Postgres session factory."""
    postgres = get_app_postgres()
    if not postgres or not postgres._session_factory:
        raise HTTPException(status_code=503, detail="Compliance service unavailable — database not connected")
    return ComplianceService(session_factory=postgres._session_factory)


@router.get("/status")
async def compliance_status(
    claims: dict = Depends(require_auth),
):
    """SOC 2 compliance health report for the current tenant."""
    service = _get_compliance_service()
    tenant_id = claims.get("tenant_id", "default")
    return await service.get_compliance_status(tenant_id)


class AuditTrailQuery(BaseModel):
    category: Optional[str] = None
    since_hours: Optional[int] = None
    limit: int = 100


@router.get("/audit-trail")
async def audit_trail(
    category: Optional[str] = Query(None),
    since_hours: Optional[int] = Query(None),
    limit: int = Query(100, le=500),
    claims: dict = Depends(require_admin),
):
    """Query the immutable compliance audit trail. Admin-only."""
    service = _get_compliance_service()
    tenant_id = claims.get("tenant_id", "default")

    since = None
    if since_hours:
        from datetime import timedelta
        since = datetime.now(timezone.utc) - timedelta(hours=since_hours)

    return await service.query_audit_trail(
        tenant_id=tenant_id,
        category=category,
        since=since,
        limit=limit,
    )


@router.post("/retention")
async def trigger_retention(
    retention_days: int = Query(90, ge=30, le=365),
    claims: dict = Depends(require_admin),
):
    """Trigger data retention enforcement. Admin-only."""
    service = _get_compliance_service()
    purged = await service.enforce_retention(retention_days=retention_days)
    return {"status": "completed", "purged_rows": purged, "retention_days": retention_days}
