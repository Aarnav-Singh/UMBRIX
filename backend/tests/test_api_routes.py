"""Unit tests for API routes."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException
from app.main import create_app
from app.dependencies import get_app_postgres, get_app_pipeline, get_app_ratelimiter
from app.middleware.auth import require_auth
from unittest.mock import AsyncMock, MagicMock
import app.dependencies as deps

# ── Test JWT claims ─────────────────────────────────────────
TEST_CLAIMS = {
    "sub": "test-admin@sentinel.local",
    "tenant_id": "default",
    "role": "admin",
    "iat": 1710000000,
    "exp": 1710099999,
}


@pytest.fixture
def mock_ratelimiter():
    limiter = MagicMock()
    limiter.check_rate_limit = AsyncMock()
    return limiter

@pytest.fixture
def mock_postgres():
    repo = MagicMock()
    repo.get_user_by_email = AsyncMock()
    return repo

@pytest.fixture
def mock_pipeline():
    svc = MagicMock()
    svc.process = AsyncMock()
    return svc

@pytest.fixture
def client(mock_ratelimiter, mock_postgres, mock_pipeline):
    app = create_app()
    from app.dependencies import get_app_ratelimiter, get_app_postgres, get_app_pipeline, get_app_clickhouse, get_app_redis

    # Mock ClickHouse and Redis for health checks
    mock_ch = MagicMock()
    mock_ch.get_event_count = AsyncMock(return_value=100)
    mock_redis = MagicMock()
    mock_redis.client = MagicMock()
    mock_redis.client.ping = AsyncMock(return_value=True)

    # Override auth — return admin claims for all protected routes
    async def _fake_auth():
        return TEST_CLAIMS

    app.dependency_overrides[require_auth] = _fake_auth
    app.dependency_overrides[get_app_ratelimiter] = lambda: mock_ratelimiter
    app.dependency_overrides[get_app_postgres] = lambda: mock_postgres
    app.dependency_overrides[get_app_pipeline] = lambda: mock_pipeline
    app.dependency_overrides[get_app_clickhouse] = lambda: mock_ch
    app.dependency_overrides[get_app_redis] = lambda: mock_redis

    # Also manually set the singletons to avoid 'assert not None' in direct getter calls
    deps._ratelimiter = mock_ratelimiter
    deps._postgres = mock_postgres
    deps._pipeline = mock_pipeline
    deps._clickhouse = mock_ch
    deps._redis = mock_redis

    test_client = TestClient(app)
    # Add Authorization header so CSRF middleware skips enforcement
    # (Bearer tokens are immune to CSRF — see middleware/csrf.py line 28-30)
    test_client.headers["Authorization"] = "Bearer test-token"
    return test_client

def test_health_check(client):
    """Test the health check endpoint with mocked dependencies."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_login_invalid_credentials(client, mock_postgres):
    """Test login with invalid credentials."""
    mock_postgres.get_user_by_email = AsyncMock(return_value=None)

    response = client.post("/api/v1/auth/login", json={"username": "wrong@example.com", "password": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

def test_ingest_rate_limit_triggered(client, mock_ratelimiter):
    """Test that rate limiting works for ingestion."""
    mock_ratelimiter.check_rate_limit = AsyncMock(side_effect=HTTPException(status_code=429))

    event_data = {
        "event_id": "test-123",
        "timestamp": "2024-03-11T00:00:00Z",
        "source": "test",
        "source_type": "firewall",
        "severity": "low",
        "metadata": {
            "tenant_id": "default",
            "source_id": "test-src"
        },
        "raw_log": "test log"
    }

    response = client.post("/api/v1/ingest/", json=event_data)
    assert response.status_code == 429

def test_ingest_success(client, mock_pipeline):
    """Test successful ingestion."""
    from app.schemas.canonical_event import MLScores, EventMetadata

    # Setup mock processed event
    mock_event = MagicMock()
    mock_event.event_id = "test-123"
    mock_event.ml_scores.meta_score = 0.5
    mock_event.metadata.pipeline_duration_ms = 10.0

    mock_pipeline.process = AsyncMock(return_value=mock_event)

    event_data = {
        "event_id": "test-123",
        "timestamp": "2024-03-11T00:00:00Z",
        "source": "test",
        "source_type": "firewall",
        "severity": "low",
        "metadata": {
            "tenant_id": "default",
            "source_id": "test-src"
        },
        "raw_log": "test log"
    }

    response = client.post("/api/v1/ingest/", json=event_data)
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
