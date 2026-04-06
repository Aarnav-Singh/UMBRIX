"""Shared test fixtures for UMBRIX.

Provides auth override fixtures so all API tests can run
without a real JWT infrastructure.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock



# ── Test JWT claims ─────────────────────────────────────────

TEST_CLAIMS_ADMIN = {
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
