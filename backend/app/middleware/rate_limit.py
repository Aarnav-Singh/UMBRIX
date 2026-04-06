"""Redis-backed sliding window rate limiter."""
from __future__ import annotations

import time
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.repositories.redis_store import RedisStore
import structlog

logger = structlog.get_logger(__name__)

class RateLimiter:
    """Sliding window rate limiter using Redis."""
    
    def __init__(self, redis_store: RedisStore):
        self._redis = redis_store

    async def check_rate_limit(
        self, 
        request: Request, 
        limit: int = 10, 
        window_seconds: int = 60,
        identifier: str | None = None
    ) -> None:
        """Check if the rate limit is exceeded for a given client IP.
        
        Args:
            request: The incoming FastAPI request.
            limit: Maximum requests allowed in the window.
            window_seconds: The duration of the sliding window in seconds.
        """
        if settings.environment == "development" and not settings.debug:
            # Optionally skip in dev, but for Phase 4 we want it active.
            pass

        key_id = identifier or (request.client.host if request.client else "unknown")
        key = f"rate_limit:{request.url.path}:{key_id}"
        now = time.time()
        
        # Use a Redis sorted set for the sliding window
        try:
            # 1. Remove old timestamps outside the window
            await self._redis._redis.zremrangebyscore(key, 0, now - window_seconds)
            
            # 2. Count requests in the current window
            request_count = await self._redis._redis.zcard(key)
            
            if request_count >= limit:
                logger.warning("rate_limit_exceeded", identifier=key_id, path=request.url.path)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again later.",
                )
            
            # 3. Add the current request timestamp
            await self._redis._redis.zadd(key, {str(now): now})
            
            # 4. Set expiration on the key to ensure it cleans up
            await self._redis._redis.expire(key, window_seconds)
            
        except Exception as exc:
            if isinstance(exc, HTTPException):
                raise
            logger.error("rate_limit_redis_error", error=str(exc))
            # FAIL-CLOSED: deny the request when Redis is unavailable.
            # A security product must never silently bypass rate limiting.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limiting service temporarily unavailable. Request denied.",
            )

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Global middleware enforcing rate limits across all /api/ paths.
    
    Adds standard rate-limit response headers:
      - ``X-RateLimit-Limit``
      - ``X-RateLimit-Remaining``
      - ``X-RateLimit-Reset``
    """
    
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):
            try:
                from app.dependencies import get_app_ratelimiter
                # We can import here to avoid circular imports during startup
                from app.middleware.tenant_isolation import get_tenant
                
                limiter = get_app_ratelimiter()
                # Determine tenant or fallback to IP
                try:
                    tenant_id = get_tenant()
                    identifier = f"tenant:{tenant_id}"
                except LookupError:
                    identifier = f"ip:{request.client.host if request.client else 'unknown'}"
                
                # Global limit: 100 requests per sliding minute window per tenant/IP
                limit = 100
                window_seconds = 60
                await limiter.check_rate_limit(request, limit=limit, window_seconds=window_seconds, identifier=identifier)

                response = await call_next(request)

                # Add rate-limit headers
                key = f"rate_limit:{request.url.path}:{identifier}"
                try:
                    remaining = max(0, limit - int(await limiter._redis._redis.zcard(key)))
                except Exception:
                    remaining = limit
                response.headers["X-RateLimit-Limit"] = str(limit)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                response.headers["X-RateLimit-Reset"] = str(window_seconds)
                return response

            except HTTPException as e:
                resp = JSONResponse(status_code=e.status_code, content={"detail": e.detail})
                resp.headers["X-RateLimit-Limit"] = "100"
                resp.headers["X-RateLimit-Remaining"] = "0"
                resp.headers["X-RateLimit-Reset"] = "60"
                return resp
            except Exception as e:
                logger.error("rate_limit_middleware_error", error=str(e))
                # Proceed on unexpected errors if not explicitly denied by limiter
        
        return await call_next(request)
