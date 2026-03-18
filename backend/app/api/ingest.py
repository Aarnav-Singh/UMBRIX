"""Ingest API — the entry point for all processed events.

POST /api/v1/ingest receives a CanonicalEvent (either from
the Kafka consumer or direct API call), validates it, and
hands it to the 15-step processing pipeline.
"""
from __future__ import annotations

import json
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel

from app.schemas.canonical_event import CanonicalEvent
from app.dependencies import get_app_pipeline, get_app_ratelimiter
from app.services.pii_masking import mask_event

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


# ── Parser stubs for cloud log sources ────────────────────
# These are lightweight wrappers; full implementations live in
# app/connectors/ and are used by the Kafka consumer.

class _StubParser:
    """Minimal parser that wraps raw dicts/strings into CanonicalEvents."""

    @staticmethod
    def parse(raw: Any) -> CanonicalEvent:
        if isinstance(raw, str):
            raw = json.loads(raw)
        return CanonicalEvent(**raw)


SyslogParser = _StubParser()
AWSCloudTrailParser = _StubParser()
GCPAuditParser = _StubParser()


class RawLogRequest(BaseModel):
    raw_log: str
    metadata: Dict[str, Any] = {}


@router.post("/", status_code=202)
async def ingest_event(
    event: CanonicalEvent,
    request: Request,
    limiter=Depends(get_app_ratelimiter),
) -> dict:
    """Accept, validate, and process a CanonicalEvent."""
    await limiter.check_rate_limit(request, limit=50, window_seconds=60)
    pipeline = get_app_pipeline()
    try:
        # Apply PII masking before pipeline processing
        masked_data = mask_event(event.model_dump())
        masked_event = CanonicalEvent(**masked_data)
        processed = await pipeline.process(masked_event)
        return {
            "status": "accepted",
            "event_id": processed.event_id,
            "meta_score": processed.ml_scores.meta_score,
            "pipeline_duration_ms": processed.metadata.pipeline_duration_ms,
        }
    except Exception:
        logger.exception("ingest_failed", event_id=event.event_id)
        raise HTTPException(status_code=500, detail="Pipeline processing failed")


@router.post("/syslog", status_code=202)
async def ingest_syslog(
    req: RawLogRequest,
    request: Request,
    limiter=Depends(get_app_ratelimiter),
) -> dict:
    await limiter.check_rate_limit(request, limit=50, window_seconds=60)
    pipeline = get_app_pipeline()
    try:
        event = SyslogParser.parse(req.raw_log)
        processed = await pipeline.process(event)
        return {
            "status": "accepted",
            "event_id": processed.event_id,
            "meta_score": processed.ml_scores.meta_score,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("syslog_ingest_failed")
        raise HTTPException(status_code=500, detail="Pipeline processing failed")


@router.post("/aws-cloudtrail", status_code=202)
async def ingest_aws_cloudtrail(
    record: Dict[str, Any],
    request: Request,
    limiter=Depends(get_app_ratelimiter),
) -> dict:
    await limiter.check_rate_limit(request, limit=50, window_seconds=60)
    pipeline = get_app_pipeline()
    try:
        event = AWSCloudTrailParser.parse(record)
        processed = await pipeline.process(event)
        return {
            "status": "accepted",
            "event_id": processed.event_id,
            "meta_score": processed.ml_scores.meta_score,
        }
    except Exception:
        logger.exception("aws_cloudtrail_ingest_failed")
        raise HTTPException(status_code=500, detail="Pipeline processing failed")


@router.post("/gcp-audit", status_code=202)
async def ingest_gcp_audit(
    log_entry: Dict[str, Any],
    request: Request,
    limiter=Depends(get_app_ratelimiter),
) -> dict:
    await limiter.check_rate_limit(request, limit=50, window_seconds=60)
    pipeline = get_app_pipeline()
    try:
        event = GCPAuditParser.parse(log_entry)
        processed = await pipeline.process(event)
        return {
            "status": "accepted",
            "event_id": processed.event_id,
            "meta_score": processed.ml_scores.meta_score,
        }
    except Exception:
        logger.exception("gcp_audit_ingest_failed")
        raise HTTPException(status_code=500, detail="Pipeline processing failed")
