"""Admin API — User and role management CRUD.

All endpoints require the ``admin`` role.
"""
from __future__ import annotations

import uuid

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.dependencies import get_app_postgres
from app.middleware.auth import require_admin, AuditLogger

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


# ── Request / Response Models ─────────────────────────
class UserCreateRequest(BaseModel):
    email: str
    password: str
    role: str = "viewer"
    display_name: str = ""
    tenant_id: str = "default"


class UserUpdateRoleRequest(BaseModel):
    role: str  # viewer | analyst | admin


class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    display_name: str | None
    tenant_id: str
    is_active: bool
    mfa_enabled: bool


# ── Endpoints ─────────────────────────────────────────

@router.get("/tenants")
async def list_tenants(
    request: Request,
    claims: dict = Depends(require_admin),
):
    """List all tenants on the platform (admin-only).

    Returns distinct tenant IDs derived from the user table plus
    a count of users in each tenant.
    """
    AuditLogger.log("admin_list_tenants", request=request, claims=claims)
    postgres = get_app_postgres()

    # Pull all users and compute per-tenant stats
    all_users = await postgres.list_users(tenant_id=None)  # None = all tenants
    tenant_map: dict[str, dict] = {}
    for u in all_users:
        tid = getattr(u, "tenant_id", "default")
        if tid not in tenant_map:
            tenant_map[tid] = {"tenant_id": tid, "user_count": 0, "admin_count": 0}
        tenant_map[tid]["user_count"] += 1
        if u.role == "admin":
            tenant_map[tid]["admin_count"] += 1

    return list(tenant_map.values())


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    request: Request,
    claims: dict = Depends(require_admin),
):
    """List all platform users (admin-only)."""
    AuditLogger.log("admin_list_users", request=request, claims=claims)
    postgres = get_app_postgres()
    tenant_id = claims.get("tenant_id", "default")

    users = await postgres.list_users(tenant_id)
    return [
        UserResponse(
            id=u.id,
            email=u.email,
            role=u.role,
            display_name=getattr(u, "display_name", None),
            tenant_id=u.tenant_id,
            is_active=u.is_active,
            mfa_enabled=getattr(u, "mfa_enabled", False),
        )
        for u in users
    ]


@router.post("/users", response_model=UserResponse, status_code=201)
async def create_user(
    body: UserCreateRequest,
    request: Request,
    claims: dict = Depends(require_admin),
):
    """Create a new user account (admin-only)."""
    postgres = get_app_postgres()

    existing = await postgres.get_user_by_email(body.email)
    if existing:
        raise HTTPException(status_code=409, detail="User already exists.")

    if body.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role. Must be viewer, analyst, or admin.")

    from app.repositories.postgres import UserRecord

    hashed = bcrypt.hashpw(body.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user = UserRecord(
        id=str(uuid.uuid4()),
        tenant_id=body.tenant_id,
        email=body.email,
        password_hash=hashed,
        role=body.role,
        display_name=body.display_name or body.email,
    )
    await postgres.create_user(user)

    AuditLogger.log("admin_user_created", request=request, claims=claims, target=body.email)
    logger.info("admin_user_created", email=body.email, role=body.role)

    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        display_name=user.display_name,
        tenant_id=user.tenant_id,
        is_active=True,
        mfa_enabled=False,
    )


@router.patch("/users/{user_email}/role")
async def update_user_role(
    user_email: str,
    body: UserUpdateRoleRequest,
    request: Request,
    claims: dict = Depends(require_admin),
):
    """Change a user's role (admin-only)."""
    if body.role not in ("viewer", "analyst", "admin"):
        raise HTTPException(status_code=400, detail="Invalid role.")

    postgres = get_app_postgres()
    user = await postgres.get_user_by_email(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    await postgres.update_user_role(email=user_email, role=body.role)

    AuditLogger.log(
        "admin_user_role_updated",
        request=request,
        claims=claims,
        target=user_email,
        detail=f"new_role={body.role}",
    )
    return {"status": "updated", "email": user_email, "role": body.role}


@router.patch("/users/{user_email}/deactivate")
async def deactivate_user(
    user_email: str,
    request: Request,
    claims: dict = Depends(require_admin),
):
    """Deactivate a user account (admin-only). Prevents future logins."""
    postgres = get_app_postgres()
    user = await postgres.get_user_by_email(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Prevent self-deactivation
    if user_email == claims.get("sub"):
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account.")

    await postgres.deactivate_user(email=user_email)

    AuditLogger.log("admin_user_deactivated", request=request, claims=claims, target=user_email)
    return {"status": "deactivated", "email": user_email}


@router.patch("/users/{user_email}/activate")
async def activate_user(
    user_email: str,
    request: Request,
    claims: dict = Depends(require_admin),
):
    """Re-activate a deactivated user account."""
    postgres = get_app_postgres()
    user = await postgres.get_user_by_email(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    await postgres.activate_user(email=user_email)

    AuditLogger.log("admin_user_activated", request=request, claims=claims, target=user_email)
    return {"status": "activated", "email": user_email}
