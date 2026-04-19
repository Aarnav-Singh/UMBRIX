import secrets
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import structlog

logger = structlog.get_logger(__name__)

class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Double Submit Cookie CSRF Protection Middleware.
    
    1. Generates a CSRF token on the first safe (GET) request.
    2. Sets it as a cookie `csrf_token`.
    3. Requires the token to be sent back in the `X-CSRF-Token` header for unsafe requests (POST, PUT, DELETE, etc.).
    """
    
    # Paths exempt from CSRF (internal/server-to-server APIs)
    EXEMPT_PREFIXES = (
        "/api/v1/simulate",
        "/api/v1/health",
        "/api/v1/events",
        "/docs",
        "/openapi.json",
        "/redoc",
    )
    
    def __init__(self, app):
        super().__init__(app)
        self.safe_methods = {"GET", "HEAD", "OPTIONS", "TRACE"}
        
    async def dispatch(self, request: Request, call_next):
        csrf_cookie = request.cookies.get("csrf_token")
        
        # Set a flag to determine if we should enforce CSRF
        should_enforce = request.method not in self.safe_methods


        # Exempt internal API paths from CSRF
        if any(request.url.path.startswith(prefix) for prefix in self.EXEMPT_PREFIXES):
            should_enforce = False
            
        # Enforce CSRF check for state-changing methods
        if should_enforce:
            csrf_header = request.headers.get("x-csrf-token")
            # If the endpoint assumes API keys or Bearer tokens, CSRF isn't strictly necessary,
            # but we enforce it here per hardening requirements.
            if not csrf_header or not csrf_cookie or csrf_header != csrf_cookie:
                logger.warning("csrf_validation_failed", client_ip=request.client.host if request.client else "unknown")
                return JSONResponse(status_code=403, content={"detail": "CSRF token missing or incorrect"})
                
        response = await call_next(request)
        
        # Set a new token if not present
        if not csrf_cookie:
            token = secrets.token_hex(32)
            response.set_cookie(
                key="csrf_token",
                value=token,
                httponly=False,  # JS needs to read it to set the header
                samesite="lax",
                secure=True  # In production, require HTTPS
            )
            
        return response
