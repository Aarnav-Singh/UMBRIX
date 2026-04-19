"""Multi-Tenancy Data Isolation Middleware.

Enforces strict tenant boundary isolation across all API requests.
Every authenticated request has its tenant_id extracted from JWT claims
and injected into a ContextVar. Repository methods use this to scope
all queries, preventing cross-tenant data leakage.

SOC 2 TSC: CC6.1, CC6.3 — Logical access and data segregation.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from starlette.types import ASGIApp

logger = structlog.get_logger(__name__)

# Module-level ContextVar — one tenant_id per async request context
tenant_ctx_var: ContextVar[str] = ContextVar("tenant_id", default="")


class TenantIsolationMiddleware(BaseHTTPMiddleware):
    """Extract tenant_id from JWT claims and enforce tenant isolation.

    Injects tenant_id into a ContextVar so all downstream repository
    queries can scope their results without explicitly passing tenant_id.
    """

    # Paths that don't require tenant context (health checks, login, simulation, etc.)
    EXEMPT_PATHS = frozenset({
        "/api/v1/auth/login",
        "/api/v1/health",
        "/health",
        "/metrics",
        "/docs",
        "/openapi.json",
    })

    # Prefixes that are exempt from tenant checks
    EXEMPT_PREFIXES = (
        "/api/v1/auth/",
        "/api/v1/simulate",
        "/api/v1/events",
    )

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # Skip tenant enforcement for exempt paths
        if path in self.EXEMPT_PATHS or any(path.startswith(p) for p in self.EXEMPT_PREFIXES):
            return await call_next(request)

        # Extract tenant_id from request state (set by auth middleware)
        tenant_id = getattr(request.state, "tenant_id", None)

        if not tenant_id:
            # Try to extract from JWT claims if auth middleware hasn't set it
            # This is a fallback; normally require_auth sets request.state
            from app.middleware.auth import decode_token
            from app.config import settings
            
            x_api_key = request.headers.get("x-api-key")
            auth_header = request.headers.get("authorization", "")
            
            logger.info("checking_proxy_auth", x_api_key=x_api_key)
            
            if x_api_key and x_api_key == settings.internal_service_api_key:
                tenant_id = "default"
            elif auth_header == f"Bearer {settings.internal_service_api_key}":
                tenant_id = "default"
            elif auth_header.startswith("Bearer "):
                try:
                    claims = decode_token(auth_header[7:])
                    tenant_id = claims.get("tenant_id", "default")
                except Exception:
                    tenant_id = None

        if not tenant_id:
            logger.warning("tenant_isolation_no_tenant", path=path)
            return JSONResponse(
                status_code=403,
                content={"detail": "Tenant context required for this endpoint"},
            )

        # Set into ContextVar for downstream usage
        token = tenant_ctx_var.set(tenant_id)
        structlog.contextvars.bind_contextvars(tenant_id=tenant_id)

        try:
            response = await call_next(request)
        finally:
            tenant_ctx_var.reset(token)

        return response


def get_current_tenant() -> str:
    """Retrieve the current request's tenant_id from the ContextVar.

    Use this in repository methods to enforce tenant scoping:

        tenant_id = get_current_tenant()
        stmt = select(Model).where(Model.tenant_id == tenant_id)
    """
    tid = tenant_ctx_var.get()
    if not tid:
        raise RuntimeError("No tenant context available — called outside request scope?")
    return tid


def get_current_tenant_or_default() -> str:
    """Like get_current_tenant() but returns 'default' instead of raising."""
    return tenant_ctx_var.get() or "default"


class TenantScopedQuery:
    """Mixin for repository classes to enforce tenant-scoped queries.

    Usage:
        class MyRepo(TenantScopedQuery):
            async def list_items(self):
                tenant_id = self.resolve_tenant()
                return await self._query(Item, tenant_id)
    """

    @staticmethod
    def resolve_tenant(explicit_tenant_id: Optional[str] = None) -> str:
        """Resolve tenant_id from explicit param or ContextVar."""
        if explicit_tenant_id:
            return explicit_tenant_id
        return get_current_tenant_or_default()
