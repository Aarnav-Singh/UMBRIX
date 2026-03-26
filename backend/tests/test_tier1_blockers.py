import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import Request, HTTPException

from app.main import app
from app.dependencies import get_app_redis
from app.middleware.rate_limit import RateLimiter
from app.middleware.auth import create_access_token


@pytest.fixture
def mock_redis():
    redis = MagicMock()
    redis.cache_get = AsyncMock(return_value=None)
    redis.cache_set = AsyncMock()
    redis._redis = AsyncMock()
    return redis


def test_jwt_logout_blocklists_token(mock_redis):
    """Test that calling /logout inserts the token's JTI into the Redis blocklist."""
    app.dependency_overrides[get_app_redis] = lambda: mock_redis
    
    # We must patch get_app_postgres to return a mock user so require_auth doesn't fail
    from app.dependencies import get_app_postgres
    mock_pg = MagicMock()
    mock_pg.get_user_by_email = AsyncMock(return_value=MagicMock(role="admin"))
    app.dependency_overrides[get_app_postgres] = lambda: mock_pg

    client = TestClient(app)
    token = create_access_token("admin@sentinel.local", "default", "admin")
    
    response = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    mock_redis.cache_set.assert_called_once()
    
    # Simulate blocked
    mock_redis.cache_get.return_value = "1"
    response2 = client.get("/api/v1/settings/environment", headers={"Authorization": f"Bearer {token}"})
    assert response2.status_code == 401
    assert "revoked" in response2.json()["detail"].lower()
    
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_sliding_window_rate_limiter(mock_redis):
    """Test that RateLimiter sliding window strictly blocks over limit."""
    # Simulate 100 requests currently in the window
    mock_redis._redis.zcard.return_value = 100
    
    limiter = RateLimiter(redis_store=mock_redis)
    
    request = MagicMock(spec=Request)
    request.client.host = "1.2.3.4"
    request.url.path = "/api/v1/test"
    
    with pytest.raises(HTTPException) as excinfo:
        await limiter.check_rate_limit(request, limit=100)
    
    assert excinfo.value.status_code == 429
    assert "Too many requests" in excinfo.value.detail
