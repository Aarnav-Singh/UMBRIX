"""UMBRIX — FastAPI Application.

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

from app.config import settings
from app.dependencies import init_dependencies, get_app_pipeline
from app.services.sse_broadcaster import SSEBroadcaster
from app.middleware.error_handler import DomainError, domain_error_handler, unhandled_error_handler
from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.csrf import CSRFMiddleware
from app.middleware.metrics import setup_metrics
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.tenant_isolation import TenantIsolationMiddleware
from app.middleware.auth import require_viewer

from app.api import ingest, health, campaigns, posture, simulation, agents, soar, collaboration, chatops
from app.api import pipeline_status, events_feed, findings, reporting, settings as settings_api, sigma_rules, vault, cases, threat_graph, cep_rules
from app.api.auth import router as auth_router
from app.services.hunting import start_hunter_scheduler

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
    from app.repositories.scylla_repository import ScyllaRepository
    from app.intelligence.stix_graph import STIXGraphRepository

    ch: ClickHouseRepository | None = None
    redis: RedisStore | None = None
    postgres: PostgresRepository | None = None
    qdrant: QdrantRepository | None = None
    scylla: ScyllaRepository | None = None
    stix: STIXGraphRepository | None = None

    # Fast port probe to detect if Docker is actually there
    async def _port_open(host, port):
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=0.5)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _connect_or_fallback(repo: Any, name: str, fallback_host: str, fallback_port: int) -> bool:
        try:
            # Add a timeout to the actual connection attempt (the repo uses its own config string)
            await asyncio.wait_for(repo.connect(), timeout=2.5)
            logger.info(f"{name}_connected")
            return True
        except Exception as e:
            logger.warning(f"{name}_connection_failed", error=str(e))
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

    # 5. ScyllaDB (Optional)
    # config.py defines scylla_contact_points: list[str] — NOT scylla_host
    scylla_contact_points = settings.scylla_contact_points
    scylla_port = getattr(settings, 'scylla_port', 9042)
    scylla = ScyllaRepository(contact_points=scylla_contact_points, port=scylla_port)
    # Use loop run_in_executor since cassandra-driver connect is synchronous
    try:
        await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, scylla.connect), 
            timeout=5.0
        )
        logger.info("scylla_connected")
    except Exception as e:
        logger.warning("scylla_unavailable_falling_back_to_postgres", error=str(e))
        scylla = None

    # 6. Memgraph (Optional STIX2 graph)
    memgraph_uri = getattr(settings, 'memgraph_uri', "bolt://localhost:7687")
    # Pass qdrant so STIX upserts also embed entities for semantic search
    stix = STIXGraphRepository(uri=memgraph_uri, user=settings.memgraph_user, password=settings.memgraph_password, qdrant=qdrant)
    try:
        await asyncio.wait_for(stix.connect(), timeout=5.0)
        await stix.initialize_schema()
        logger.info("memgraph_stix2_initialized")
    except Exception as e:
        logger.warning("memgraph_unavailable", error=str(e))
        stix = None

    if pg_ok:
        import bcrypt
        
        # CRIT-07: Never seed hardcoded default credentials.
        # Use environment variables or a dedicated bootstrap script in production.
        logger.info("skipping_default_user_seed", reason="security_hardening")

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

    # 5. Initialize SSE Broadcaster
    broadcaster = SSEBroadcaster()

    # Pass deps to global container
    init_dependencies(
        ch=ch,
        redis=redis,
        postgres=postgres,
        qdrant=qdrant,
        scylla=scylla,
        stix=stix,
        broadcaster=broadcaster
    )

    # Start Vault background polling for runtime secret rotation
    asyncio.create_task(settings.start_vault_polling())

    import json
    if redis_ok:
        async def _redis_pubsub_listener():
            try:
                await asyncio.sleep(2) # Give dependencies time to initialize
                if not hasattr(redis, "_client") or not redis._client:
                    return
                pubsub = redis._client.pubsub()
                await pubsub.subscribe("live_events", "cep_rules_updated")
                
                from app.dependencies import get_app_broadcaster
                app_broadcaster = get_app_broadcaster()
                
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        try:
                            channel = message["channel"].decode("utf-8")
                            payload = message["data"].decode("utf-8")
                            if channel == "live_events":
                                payload_dict = json.loads(payload)
                                tenant_id = payload_dict.get("metadata", {}).get("tenant_id", "default")
                                await app_broadcaster.broadcast(payload_dict, tenant_id=tenant_id)
                            elif channel == "cep_rules_updated":
                                # Payload is the tenant_id string
                                pipeline = get_app_pipeline()
                                if pipeline._cep:
                                    pipeline._cep.invalidate_tenant(payload)
                                    logger.info("cep_rules_cache_invalidated", tenant_id=payload)
                        except Exception as e:
                            logger.debug("redis_pubsub_forward_error", channel=channel, error=str(e))
            except Exception as e:
                logger.error("redis_pubsub_listener_failed", error=str(e))

        asyncio.create_task(_redis_pubsub_listener())
    if ch_ok and redis_ok:
        logger.info("starting_infrastructure_consumers")
        from app.consumers.event_consumer import EventConsumer
        
        # Start Background Schedulers
        if pg_ok and qdrant_ok:
            start_hunter_scheduler()
        
        if pg_ok:
            from app.services.compliance import start_compliance_scheduler
            start_compliance_scheduler()

            # TAXII threat intel feed sync scheduler
            from app.intelligence.taxii_scheduler import run_taxii_sync
            if settings.stix2_taxii_feeds:
                async def _taxii_loop() -> None:
                    while True:
                        try:
                            await run_taxii_sync()
                        except Exception as _e:
                            logger.warning("taxii_sync_error", error=str(_e))
                        await asyncio.sleep(settings.stix2_pull_interval_hours * 3600)
                asyncio.create_task(_taxii_loop())
                logger.info("taxii_scheduler_started", feeds=len(settings.stix2_taxii_feeds))

            # Agent Lightning model retraining scheduler (Phase 34C)
            from app.services.model_retrainer import schedule_retraining
            schedule_retraining(postgres=postgres, ensemble=get_app_pipeline()._ensemble)
        
        # For cloud Kafka (Upstash/SASL), skip the localhost port probe entirely.
        # For local Docker, probe localhost:9092 as before.
        cloud_kafka = settings.kafka_security_protocol != "PLAINTEXT"
        kafka_reachable = cloud_kafka or await _port_open("localhost", 9092)

        # Build shared SASL kwargs used by every Kafka client in this process.
        kafka_sasl_kwargs: dict = {}
        if cloud_kafka:
            kafka_sasl_kwargs = {
                "security_protocol": settings.kafka_security_protocol,
                "sasl_mechanism": settings.kafka_sasl_mechanism,
                "sasl_plain_username": settings.kafka_sasl_username,
                "sasl_plain_password": settings.kafka_sasl_password,
            }

        if kafka_reachable:
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

            # Phase 1: Wire CEP Kafka producer into pipeline and start CEP consumer
            async def _start_cep_infrastructure():
                """Give Kafka 2s to stabilise then wire CEP producer + consumer."""
                await asyncio.sleep(2)
                try:
                    from aiokafka import AIOKafkaProducer
                    pipeline = get_app_pipeline()

                    cep_producer = AIOKafkaProducer(
                        bootstrap_servers=settings.kafka_bootstrap_servers,
                        value_serializer=lambda v: v,
                        **kafka_sasl_kwargs,
                    )
                    await cep_producer.start()
                    pipeline._cep_producer = cep_producer
                    logger.info("cep_producer_wired")

                    from app.consumers.cep_consumer import CEPConsumer
                    cep_consumer = CEPConsumer(
                        pipeline=pipeline,
                        kafka_bootstrap=settings.kafka_bootstrap_servers,
                        kafka_sasl_kwargs=kafka_sasl_kwargs,
                    )
                    await cep_consumer.start()
                    asyncio.create_task(cep_consumer.run())
                    logger.info("cep_consumer_task_scheduled")
                except Exception as e:
                    logger.warning("cep_infrastructure_start_failed", error=str(e))

            asyncio.create_task(_start_cep_infrastructure())
        else:
            logger.warning("kafka_port_closed_skipping_consumer")
    else:
        logger.warning("using_in_memory_fallbacks_some_features_disabled")

    # ── Triage Queue Worker ────────────────────────────────
    # Non-blocking background worker for LLM auto-triage.
    # Recovers stale items from crashed workers on startup.
    if redis_ok:
        pipeline = get_app_pipeline()
        triage_queue = pipeline._triage_queue

        # Recover events stuck in processing from a previous crash
        recovered = await triage_queue.recover_stale_processing("default")
        if recovered:
            logger.info("triage_queue_recovered_stale_items", count=recovered)

        async def _triage_worker_loop():
            try:
                await triage_queue.start_worker("default")
            except Exception as e:
                logger.error("triage_worker_crashed", error=str(e))

        asyncio.create_task(_triage_worker_loop())
        logger.info("triage_queue_worker_started")

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
        {"name": "threat-hunt", "description": "UQL threat hunting — ML-aware query language and natural-language interpretation"},
    ]

    app = FastAPI(
        title="UMBRIX",
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
            "url": "https://umbrix.io/license",
        },
        contact={
            "name": "UMBRIX Security Team",
            "email": "security@umbrix.io",
        },
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
    )

    # Prometheus Metrics
    setup_metrics(app)

    # Security Headers
    app.add_middleware(SecurityHeadersMiddleware)
    
    # API Rate Limiter — must run after TenantIsolationMiddleware
    from app.middleware.rate_limit import RateLimitMiddleware
    app.add_middleware(RateLimitMiddleware)
    
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
    app.include_router(vault.router, prefix="/api/v1")
    app.include_router(collaboration.router, prefix="/api/v1")
    app.include_router(collaboration.rest_router)   # HTTP annotation + presence endpoints
    app.include_router(chatops.router, prefix="/api/v1")
    
    # Compliance API (SOC 2 audit trail + status)
    from app.api.compliance import router as compliance_router
    app.include_router(compliance_router, prefix="/api/v1")

    # Asset Management API (CMDB registration)
    from app.api.assets import router as assets_router
    app.include_router(assets_router, prefix="/api/v1")

    # Admin API (user management)
    from app.api.admin import router as admin_router
    app.include_router(admin_router, prefix="/api/v1")

    # Search API (omnibar search)
    from app.api.search import router as search_router
    app.include_router(search_router, prefix="/api/v1")

    # Threat Hunt API — Phase 3 (UQL Engine)
    from app.api.hunt import router as hunt_router
    from app.api.hunt_history import router as hunt_history_router
    from app.api.cases import router as cases_router
    app.include_router(hunt_router, prefix="/api/v1")
    app.include_router(hunt_history_router, prefix="/api/v1")
    app.include_router(cases_router, prefix="/api/v1")
    app.include_router(threat_graph.router)

    # Grouped Events API (CEP sequence aggregation — AttackPatternCard)
    from app.api.events_grouped import router as events_grouped_router
    app.include_router(events_grouped_router, prefix="/api/v1")

    # CEP Rules API (Phase 3)
    app.include_router(cep_rules.router, prefix="/api/v1")

    # Entity Details API (Investigation Console F-01)
    from app.api.entity_details import router as entity_details_router
    app.include_router(entity_details_router, prefix="/api/v1")

    # Narrative Generation API (AI Summarize)
    from app.api.narrative import router as narrative_router
    app.include_router(narrative_router, prefix="/api/v1")

    # Tenant-scoped SSE stream
    @app.get("/api/v1/events/stream")
    async def sse_events(
        request: Request,
        claims: dict = Depends(require_viewer)
    ):
        subscriber_id = str(uuid.uuid4())
        tenant_id = claims.get("tenant_id", "default")
        from sse_starlette.sse import EventSourceResponse
        from app.dependencies import get_app_broadcaster
        
        broadcaster = get_app_broadcaster()
        
        return EventSourceResponse(
            broadcaster.event_stream(tenant_id, subscriber_id),
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
            }
        )

    return app

app = create_app()
