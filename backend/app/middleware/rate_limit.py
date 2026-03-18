"""Redis-backed sliding window rate limiter."""
from __future__ import annotations

import time
from fastapi import Request, HTTPException, status
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
        window_seconds: int = 60
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

        client_ip = request.client.host if request.client else "unknown"
        key = f"rate_limit:{request.url.path}:{client_ip}"
        now = time.time()
        
        # Use a Redis sorted set for the sliding window
        try:
            # 1. Remove old timestamps outside the window
            await self._redis._redis.zremrangebyscore(key, 0, now - window_seconds)
            
            # 2. Count requests in the current window
            request_count = await self._redis._redis.zcard(key)
            
            if request_count >= limit:
                logger.warning("rate_limit_exceeded", ip=client_ip, path=request.url.path)
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
