"""Dependency container — wires repositories and services at app startup.

Singleton instances are created during the FastAPI lifespan and
accessed via these module-level getters. No global mutable state.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from app.repositories.clickhouse import ClickHouseRepository
from app.repositories.redis_store import RedisStore
from app.repositories.postgres import PostgresRepository
from app.repositories.qdrant_store import QdrantRepository
from app.services.sse_broadcaster import SSEBroadcaster
from app.services.pipeline import PipelineService
from app.services.soar.engine import ExecutionEngine

if TYPE_CHECKING:
    from app.middleware.rate_limit import RateLimiter

# ── Singletons (set during lifespan) ────────────────────

_clickhouse: ClickHouseRepository | None = None
_redis: RedisStore | None = None
_postgres: PostgresRepository | None = None
_qdrant: QdrantRepository | None = None
_broadcaster: SSEBroadcaster | None = None
_pipeline: PipelineService | None = None
_ratelimiter: RateLimiter | None = None
_engine: ExecutionEngine | None = None


def init_dependencies(
    ch: ClickHouseRepository,
    redis: RedisStore,
    postgres: PostgresRepository,
    qdrant: QdrantRepository,
    broadcaster: SSEBroadcaster,
) -> None:
    global _clickhouse, _redis, _postgres, _qdrant, _broadcaster, _pipeline, _engine
    _clickhouse = ch
    _redis = redis
    _postgres = postgres
    _qdrant = qdrant
    _broadcaster = broadcaster
    
    from app.middleware.rate_limit import RateLimiter
    _ratelimiter = RateLimiter(redis_store=redis)
    
    _engine = ExecutionEngine(postgres_repo=postgres)
    
    from app.config import settings
    _pipeline = PipelineService(
        clickhouse=ch,
        redis=redis,
        qdrant=qdrant,
        postgres=postgres,
        broadcaster=broadcaster,
        narrative_mode=settings.narrative_mode,
        anthropic_key=settings.anthropic_api_key,
        openai_key=settings.openai_api_key,
        llama_cpp_model=settings.llama_cpp_model,
        llama_cpp_base_url=settings.llama_cpp_base_url,
        llama_cpp_temperature=settings.llama_cpp_temperature,
        llama_cpp_max_tokens=settings.llama_cpp_max_tokens,
    )


def get_app_clickhouse() -> ClickHouseRepository:
    assert _clickhouse is not None, "ClickHouse not initialized"
    return _clickhouse


def get_app_redis() -> RedisStore:
    assert _redis is not None, "Redis not initialized"
    return _redis


def get_app_postgres() -> PostgresRepository:
    assert _postgres is not None, "Postgres not initialized"
    return _postgres


def get_app_qdrant() -> QdrantRepository:
    assert _qdrant is not None, "Qdrant not initialized"
    return _qdrant


def get_app_broadcaster() -> SSEBroadcaster:
    assert _broadcaster is not None, "SSE broadcaster not initialized"
    return _broadcaster


def get_app_pipeline() -> PipelineService:
    assert _pipeline is not None, "Pipeline not initialized"
    return _pipeline


def get_app_ratelimiter() -> RateLimiter:
    assert _ratelimiter is not None, "RateLimiter not initialized"
    return _ratelimiter


def get_app_engine() -> ExecutionEngine:
    assert _engine is not None, "ExecutionEngine not initialized"
    return _engine
