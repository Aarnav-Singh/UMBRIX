"""JWT Authentication middleware — self-issued tokens.

Enterprise customers deploy on-prem without Google dependency.
The backend issues and validates its own JWTs.

Security patterns guided by:
  - @auth-implementation-patterns (role hierarchy, token lifecycle)
  - @cc-skill-security-review (authorization checks before sensitive ops)
  - @fastapi-pro (FastAPI dependency injection for RBAC)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional
import uuid

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from jose import JWTError, jwt

from app.config import settings

import structlog

logger = structlog.get_logger(__name__)

_security = HTTPBearer(auto_error=False)


# ── Role Hierarchy ────────────────────────────────────────
# Per @auth-implementation-patterns: define a role hierarchy
# so admin inherits analyst permissions, analyst inherits viewer.

class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


# Higher index = more privileges
_ROLE_LEVEL = {
    Role.VIEWER: 0,
    Role.ANALYST: 1,
    Role.ADMIN: 2,
}


def _has_minimum_role(user_role: str, required_role: Role) -> bool:
    """Check if user_role meets or exceeds the required role level."""
    try:
        user_level = _ROLE_LEVEL[Role(user_role)]
    except (ValueError, KeyError):
        return False
    return user_level >= _ROLE_LEVEL[required_role]


# ── Token Creation & Validation ───────────────────────────

def create_access_token(
    subject: str,
    tenant_id: str = "default",
    role: str = "analyst",
    extra_claims: Optional[dict] = None,
) -> str:
    """Issue a new JWT."""
    now = datetime.now(timezone.utc)
    claims = {
        "jti": str(uuid.uuid4()),
        "sub": subject,
        "tenant_id": tenant_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expiry_minutes),
    }
    if extra_claims:
        claims.update(extra_claims)
    return jwt.encode(claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    """Validate and decode a JWT. Raises on failure."""
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
    except JWTError as exc:
        if settings.jwt_fallback_secret_key:
            try:
                return jwt.decode(token, settings.jwt_fallback_secret_key, algorithms=[settings.jwt_algorithm])
            except JWTError:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
        ) from exc


# ── FastAPI Dependencies ──────────────────────────────────
# Per @fastapi-pro: use Depends() for clean auth injection.

async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
) -> dict:
    """FastAPI dependency — require a valid JWT on the request or a valid internal API key."""
    # Check for internal service-to-service header
    x_api_key = request.headers.get("x-api-key")
    if x_api_key and x_api_key == settings.internal_service_api_key:
        return {
            "jti": f"internal-service-{uuid.uuid4()}",
            "sub": "internal-service",
            "tenant_id": "default",
            "role": "admin"
        }

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )
    
    # Try to decode token. If it's the raw API key (passed as Bearer fallback), intercept it
    if credentials.credentials == settings.internal_service_api_key:
        return {
            "jti": f"internal-service-{uuid.uuid4()}",
            "sub": "internal-service",
            "tenant_id": "default",
            "role": "admin"
        }

    claims = decode_token(credentials.credentials)
    
    jti = claims.get("jti")
    if jti:
        from app.dependencies import get_app_redis
        redis = get_app_redis()
        is_blocked = await redis.cache_get(f"blocked_jti:{jti}")
        if is_blocked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked",
            )
            
    return claims


def require_role(minimum_role: Role):
    """Factory for role-based access control dependencies.

    Returns a FastAPI-compatible dependency that checks the JWT
    claims against a minimum role level using the role hierarchy.

    Per @auth-implementation-patterns: RBAC with role hierarchy.

    Usage:
        @router.delete("/users/{id}", dependencies=[Depends(require_role(Role.ADMIN))])
        async def delete_user(id: str): ...
    """
    async def _check(
        claims: dict = Depends(require_auth),
    ) -> dict:
        user_role = claims.get("role", "viewer")
        if not _has_minimum_role(user_role, minimum_role):
            logger.warning(
                "rbac_denied",
                user=claims.get("sub"),
                user_role=user_role,
                required_role=minimum_role.value,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Minimum role '{minimum_role.value}' required",
            )
        return claims
    return _check


# Convenience shortcuts
require_admin = require_role(Role.ADMIN)
require_analyst = require_role(Role.ANALYST)
require_viewer = require_role(Role.VIEWER)


# ── Audit Logger ──────────────────────────────────────────
# Per @cc-skill-security-review: log security events.

class AuditLogger:
    """Structured audit trail for security-sensitive actions.

    Logs to structlog with the 'audit' event type so they can
    be routed to a dedicated audit sink (e.g., ClickHouse,
    Postgres audit_logs table, or SIEM).
    """

    @staticmethod
    def log(
        action: str,
        *,
        request: Optional[Request] = None,
        claims: Optional[dict] = None,
        target: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        """Emit a structured audit log entry."""
        log_data = {
            "action": action,
            "user": claims.get("sub") if claims else "anonymous",
            "tenant_id": claims.get("tenant_id") if claims else "unknown",
            "role": claims.get("role") if claims else "none",
            "target": target,
            "detail": detail,
        }
        if request:
            log_data["client_ip"] = request.client.host if request.client else "unknown"
            log_data["method"] = request.method
            log_data["path"] = str(request.url.path)

        logger.info("audit_event", **log_data)


# ── Attribute-Based Access Control (ABAC) ────────────────
# Adds data masking capabilities on top of RBAC.

class ClearanceLevel(int, Enum):
    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2

class ABACPolicy:
    @staticmethod
    def mask_entity(data: dict, claims: dict) -> dict:
        """Masks PII and sensitive attributes based on clearance."""
        masked_data = data.copy()
        clearance = claims.get("clearance", ClearanceLevel.UNCLASSIFIED.value)
        
        # Enforce Tenant Isolation boundaries
        if "tenant_id" in masked_data and masked_data["tenant_id"] != claims.get("tenant_id", "default"):
            raise HTTPException(status_code=403, detail="ABAC Violation: Tenant boundary crossed")
            
        # Enforce Clearance Boundaries
        if clearance < ClearanceLevel.SECRET.value:
            if "username" in masked_data:
                masked_data["username"] = "***MASKED***"
            if "src_ip" in masked_data and not str(masked_data["src_ip"]).startswith("10."):
                masked_data["src_ip"] = "***MASKED***"
                
        return masked_data

