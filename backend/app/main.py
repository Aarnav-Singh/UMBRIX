"""Sentinel Fabric V2 — FastAPI Application.

Lifespan hooks initialize all database connections and services.
"""
from __future__ import annotations

import asyncio
import uuid
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.dependencies import init_dependencies, get_app_pipeline
from app.services.sse_broadcaster import SSEBroadcaster
from app.middleware.error_handler import DomainError, domain_error_handler, unhandled_error_handler
from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.csrf import CSRFMiddleware
from app.middleware.metrics import setup_metrics
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.tenant_isolation import TenantIsolationMiddleware

from app.api import ingest, health, campaigns, posture, simulation, agents, soar, collaboration, chatops
from app.api import pipeline_status, events_feed, findings, reporting, settings as settings_api, sigma_rules
from app.api.auth import router as auth_router
from app.services.hunting import start_hunter_scheduler
from app.services.compliance_digest import run_compliance_digest_job

import structlog

_log_level_map = {"DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR}

structlog.configure(
    processors=[
        # Merge any context vars bound by RequestIDMiddleware (request_id etc.)
        # into every log record emitted during the request.
        structlog.contextvars.merge_contextvars,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        _log_level_map.get(settings.log_level.upper(), logging.INFO)
    ),
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle hook for startup and shutdown."""
    logger.info("application_startup_begins", version=settings.version)

    # 1. Initialize core infrastructure dependencies
    from app.repositories.clickhouse import ClickHouseRepository
    from app.repositories.redis_store import RedisStore
    from app.repositories.postgres import PostgresRepository, UserRecord
    from app.repositories.qdrant_store import QdrantRepository

    ch: ClickHouseRepository | None = None
    redis: RedisStore | None = None
    postgres: PostgresRepository | None = None
    qdrant: QdrantRepository | None = None

    # Fast port probe to detect if Docker is actually there
    async def _port_open(host, port):
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.5)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def _connect_or_fallback(repo: Any, name: str, host: str, port: int) -> bool:
        if await _port_open(host, port):
            try:
                # Add a timeout to the actual connection attempt
                await asyncio.wait_for(repo.connect(), timeout=1.5)
                logger.info(f"{name}_connected", host=host, port=port)
                return True
            except Exception as e:
                logger.warning(f"{name}_connection_failed", error=str(e))
        else:
            logger.warning(f"{name}_port_closed", host=host, port=port)
        return False

    # Try connecting to Docker infra
    # 1. ClickHouse
    ch = ClickHouseRepository()
    ch_ok = await _connect_or_fallback(ch, "clickhouse", settings.clickhouse_host, settings.clickhouse_port)

    # 2. Redis
    redis = RedisStore()
    redis_ok = await _connect_or_fallback(redis, "redis", settings.redis_host, settings.redis_port)

    # 3. PostgreSQL
    postgres = PostgresRepository()
    pg_ok = await _connect_or_fallback(postgres, "postgres", settings.postgres_host, settings.postgres_port)

    # 4. Qdrant
    qdrant = QdrantRepository()
    qdrant_ok = await _connect_or_fallback(qdrant, "qdrant", settings.qdrant_host, settings.qdrant_port)

    if pg_ok:
        import bcrypt
        
        # Seed default users ONLY in development mode.
        # In production, these default credentials are a critical vulnerability.
        if settings.environment == "development":
            admin = await postgres.get_user_by_email("admin")
            if not admin:
                logger.info("seeding_default_users", note="development-only")
                await postgres.create_user(UserRecord(
                    id=str(uuid.uuid4()),
                    tenant_id="default",
                    email="admin",
                    password_hash=bcrypt.hashpw(b"admin", bcrypt.gensalt()).decode('utf-8'),
                    role="admin",
                    display_name="System Administrator"
                ))
                await postgres.create_user(UserRecord(
                    id=str(uuid.uuid4()),
                    tenant_id="default",
                    email="analyst",
                    password_hash=bcrypt.hashpw(b"analyst", bcrypt.gensalt()).decode('utf-8'),
                    role="analyst",
                    display_name="Security Analyst"
                ))
        else:
            logger.info("skipping_default_user_seed", environment=settings.environment)

        # Seed default connectors
        from app.repositories.postgres import ConnectorRecord
        from datetime import datetime
        import json
        existing_connectors = await postgres.list_connectors("default")
        if not existing_connectors:
            logger.info("seeding_default_connectors")
            await postgres.save_connector(ConnectorRecord(
                id=str(uuid.uuid4()),
                tenant_id="default",
                name="Core Zeek Sensor",
                source_type="zeek",
                connection_pattern="push",
                config_json=json.dumps({"interface": "eth0"}),
                created_at=datetime.utcnow()
            ))
            await postgres.save_connector(ConnectorRecord(
                id=str(uuid.uuid4()),
                tenant_id="default",
                name="Suricata IPS",
                source_type="suricata",
                connection_pattern="push",
                config_json=json.dumps({"ruleset": "et-open"}),
                created_at=datetime.utcnow()
            ))
            await postgres.save_connector(ConnectorRecord(
                id=str(uuid.uuid4()),
                tenant_id="default",
                name="Windows Event Forwarder",
                source_type="windows_event",
                connection_pattern="pull",
                config_json=json.dumps({"port": 514}),
                created_at=datetime.utcnow()
            ))

    # 2. Initialize orchestration services
    broadcaster = SSEBroadcaster()
    init_dependencies(
        ch=ch,
        redis=redis,
        postgres=postgres,
        qdrant=qdrant,
        broadcaster=broadcaster,
    )

    # 3. Start background consumers and schedulers (if infra is healthy)
    if ch_ok and redis_ok:
        logger.info("starting_infrastructure_consumers")
        from app.consumers.event_consumer import EventConsumer
        
        # Start Automated Threat Hunting Scheduler
        if pg_ok and qdrant_ok:
            start_hunter_scheduler()
        
        # Check Kafka port (9092) first
        if await _port_open("localhost", 9092):
            async def _safe_kafka_consumer():
                """Run Kafka consumer with retry; never crash the server."""
                try:
                    consumer = EventConsumer(get_app_pipeline())
                    await consumer.start()
                    await consumer.run()
                except Exception as e:
                    logger.warning("kafka_consumer_background_error", error=str(e))

            asyncio.create_task(_safe_kafka_consumer())
            logger.info("kafka_consumer_task_scheduled")
        else:
            logger.warning("kafka_port_closed_skipping_consumer")
    else:
        logger.warning("using_in_memory_fallbacks_some_features_disabled")

    yield

    # Shutdown
    await redis.close()
    await postgres.close()
    logger.info("application_shutdown_complete")


def create_app() -> FastAPI:
    """FastAPI Application Factory."""
    openapi_tags = [
        {"name": "auth", "description": "Authentication, MFA enrollment, and session management"},
        {"name": "ingest", "description": "Event ingestion from Suricata, Zeek, Windows, CrowdStrike, Palo Alto, Syslog"},
        {"name": "health", "description": "Health checks and system status"},
        {"name": "campaigns", "description": "Threat campaign correlation and kill-chain tracking"},
        {"name": "posture", "description": "Security posture scoring and compliance dashboards"},
        {"name": "soar", "description": "SOAR playbook execution, conditional branching, and audit trail"},
        {"name": "findings", "description": "Security findings and alert management"},
        {"name": "sigma", "description": "Sigma detection rules management"},
        {"name": "reporting", "description": "Compliance reports and executive summaries"},
        {"name": "collaboration", "description": "Incident annotations, tagging, and team collaboration"},
        {"name": "simulation", "description": "Attack simulation and red team tooling"},
        {"name": "compliance", "description": "SOC 2 Type II audit trail and compliance status"},
    ]

    app = FastAPI(
        title="Sentinel Fabric V2",
        description=(
            "Enterprise Security Posture Intelligence Platform. "
            "Real-time ML-powered threat detection, SOAR orchestration, "
            "campaign correlation, and SOC 2 Type II compliant audit trails."
        ),
        version=settings.version,
        lifespan=lifespan,
        openapi_tags=openapi_tags,
        license_info={
            "name": "Proprietary",
            "url": "https://sentinelfabric.io/license",
        },
        contact={
            "name": "Sentinel Fabric Security Team",
            "email": "security@sentinelfabric.io",
        },
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Prometheus Metrics
    setup_metrics(app)

    # Security Headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # Tenant Isolation — extracts tenant_id from JWT into ContextVar
    app.add_middleware(TenantIsolationMiddleware)
    
    # CSRF Protection
    app.add_middleware(CSRFMiddleware)

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Error Handlers
    app.add_exception_handler(DomainError, domain_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)

    # Request ID Correlation — MUST be added last so it becomes the outermost
    # middleware layer (last add_middleware call = first to execute).
    # This guarantees the request_id ContextVar is set before any route handler,
    # exception handler, or inner middleware runs.
    app.add_middleware(RequestIDMiddleware)

    # Register API Routers
    app.include_router(auth_router)
    app.include_router(ingest.router, prefix="/api/v1")
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(campaigns.router, prefix="/api/v1")
    app.include_router(posture.router, prefix="/api/v1")
    app.include_router(simulation.router, prefix="/api/v1")
    # V2 routers
    app.include_router(pipeline_status.router)
    app.include_router(events_feed.router)
    app.include_router(findings.router)
    app.include_router(agents.router, prefix="/api/v1")
    app.include_router(sigma_rules.router, prefix="/api/v1")
    app.include_router(reporting.router, prefix="/api/v1")
    app.include_router(settings_api.router, prefix="/api/v1")
    app.include_router(soar.router, prefix="/api/v1")
    app.include_router(collaboration.router, prefix="/api/v1")
    app.include_router(chatops.router, prefix="/api/v1")
    
    # Compliance API (SOC 2 audit trail + status)
    from app.api.compliance import router as compliance_router
    app.include_router(compliance_router, prefix="/api/v1")

    # Tenant-scoped SSE stream
    @app.get("/api/v1/events/stream")
    async def sse_events(request: Request):
        subscriber_id = str(uuid.uuid4())
        from sse_starlette.sse import EventSourceResponse
        from app.dependencies import get_app_broadcaster
        
        broadcaster = get_app_broadcaster()
        
        return EventSourceResponse(
            broadcaster.event_stream(subscriber_id),
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            }
        )

    return app

app = create_app()
