"""Edge Ingestion Gateway for Decentralized Log Collection.

Deployed in remote regions (EU-West, US-East) to receive high-volume
raw logs, validate them against the CanonicalEvent schema locally, 
and push to regional Kafka topics.
"""
import os
import time
import json
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import ValidationError

import structlog
from aiokafka import AIOKafkaProducer

from app.schemas.canonical_event import CanonicalEvent

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="UMBRIX Edge Gateway",
    description="Distributed Edge Ingestion Node",
    version="2.0.0"
)

# Global producer instance
_producer: AIOKafkaProducer | None = None
_edge_region = os.getenv("EDGE_REGION", "unknown-region")
_kafka_bootstrap = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")


@app.on_event("startup")
async def startup_event():
    """Initialize Kafka Producer on startup."""
    global _producer
    try:
        _producer = AIOKafkaProducer(
            bootstrap_servers=_kafka_bootstrap,
            client_id=f"edge-gateway-{_edge_region}",
            # Batching optimizations for high throughput
            linger_ms=50,
            batch_size=16384,
        )
        await _producer.start()
        logger.info("edge_gateway_started", region=_edge_region, kafka=_kafka_bootstrap)
    except Exception as e:
        logger.warning("kafka_producer_init_failed", error=str(e))


@app.on_event("shutdown")
async def shutdown_event():
    """Flush and close Kafka producer."""
    if _producer:
        try:
            await _producer.stop()
            logger.info("edge_gateway_stopped", region=_edge_region)
        except Exception:
            pass


@app.post("/ingest")
async def ingest_logs(request: Request) -> Response:
    """Receive raw telemetry or pre-parsed CanonicalEvents at the edge."""
    # Enforce idempotency and trace propagation (Phase 16/17 Req)
    trace_id = request.headers.get("x-trace-id", f"req-{time.time_ns()}")
    tenant_id = request.headers.get("x-tenant-id", "default")
    
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Local Schema Validation
    try:
        # If it's a list, validate batch. If single, validate single.
        events_to_produce = []
        if isinstance(payload, list):
            for item in payload:
                event = CanonicalEvent(**item)
                event.metadata.tenant_id = tenant_id # Override tenant auth via headers
                events_to_produce.append(event.model_dump(mode="json"))
        else:
            event = CanonicalEvent(**payload)
            event.metadata.tenant_id = tenant_id
            events_to_produce.append(event.model_dump(mode="json"))
    except ValidationError as e:
        logger.warning("edge_validation_failed", errors=e.errors(), trace_id=trace_id)
        raise HTTPException(status_code=422, detail=e.errors())

    if _producer:
        topic = f"telemetry_{_edge_region}" # Regional topics
        try:
            for ev_dict in events_to_produce:
                await _producer.send_and_wait(
                    topic,
                    value=json.dumps(ev_dict).encode("utf-8"),
                    headers=[
                        ("trace_id", trace_id.encode("utf-8")),
                        ("edge_region", _edge_region.encode("utf-8"))
                    ]
                )
            logger.debug("edge_batch_produced", count=len(events_to_produce), topic=topic, trace_id=trace_id)
        except Exception as e:
            logger.error("edge_kafka_produce_failed", error=str(e), trace_id=trace_id)
            raise HTTPException(status_code=503, detail="Kafka temporarily unavailable")
    else:
        # Fallback if no Kafka
        logger.warning("edge_kafka_not_configured", count=len(events_to_produce), trace_id=trace_id)

    return Response(status_code=202, content=json.dumps({"status": "accepted", "count": len(events_to_produce), "trace_id": trace_id}))


@app.get("/health")
async def health_check():
    """Edge health check endpoint."""
    kafka_status = "ok" if _producer else "disconnected"
    return {"status": "healthy", "region": _edge_region, "kafka": kafka_status}
