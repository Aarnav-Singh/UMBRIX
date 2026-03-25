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


# ── Real parsers for cloud log sources ────────────────────
import re
from datetime import datetime, timezone

from app.schemas.canonical_event import (
    ActionType, OutcomeType, SeverityLevel, NetworkInfo, Entity, EntityType, EventMetadata,
)

_SYSLOG_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

_SYSLOG_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>\d?\s*"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?:\[.*?\]\s*)?"
    r"(?P<message>.*)$"
)

_SYSLOG_SEVERITY_MAP = {
    0: SeverityLevel.CRITICAL, 1: SeverityLevel.CRITICAL,
    2: SeverityLevel.CRITICAL, 3: SeverityLevel.HIGH,
    4: SeverityLevel.MEDIUM,   5: SeverityLevel.LOW,
    6: SeverityLevel.INFO,     7: SeverityLevel.INFO,
}

_IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class _SyslogParser:
    """Parse RFC 3164/5424 syslog messages into CanonicalEvents."""

    @staticmethod
    def parse(raw: str) -> CanonicalEvent:
        match = _SYSLOG_RFC5424.match(raw) or _SYSLOG_RFC3164.match(raw)
        if not match:
            raise ValueError(f"Unparseable syslog message: {raw[:120]}")

        groups = match.groupdict()
        pri = int(groups.get("pri", 6 * 8 + 6))
        sev_num = pri & 0x07
        severity = _SYSLOG_SEVERITY_MAP.get(sev_num, SeverityLevel.INFO)

        message = groups.get("message", raw)
        hostname = groups.get("hostname", "unknown")
        app = groups.get("app", "")

        # Try to extract IP addresses from message
        ips = _IP_PATTERN.findall(message)
        src_ip = ips[0] if len(ips) >= 1 else None
        dst_ip = ips[1] if len(ips) >= 2 else None

        action = ActionType.ALERT if sev_num <= 4 else ActionType.UNKNOWN

        return CanonicalEvent(
            source_type="syslog",
            event_category="syslog",
            event_type=app,
            severity=severity,
            action=action,
            outcome=OutcomeType.UNKNOWN,
            message=message,
            network=NetworkInfo(src_ip=src_ip, dst_ip=dst_ip) if src_ip else None,
            source_entity=Entity(entity_type=EntityType.HOST, identifier=hostname),
            metadata=EventMetadata(parser_name="syslog", raw_log=raw),
        )


class _AWSCloudTrailParser:
    """Parse AWS CloudTrail JSON records into CanonicalEvents."""

    _SEVERITY_MAP = {
        "ConsoleLogin": SeverityLevel.MEDIUM,
        "StopLogging": SeverityLevel.CRITICAL,
        "DeleteTrail": SeverityLevel.CRITICAL,
        "AuthorizeSecurityGroupIngress": SeverityLevel.HIGH,
        "RunInstances": SeverityLevel.MEDIUM,
        "CreateUser": SeverityLevel.HIGH,
        "AttachUserPolicy": SeverityLevel.HIGH,
    }

    @staticmethod
    def parse(raw: Any) -> CanonicalEvent:
        if isinstance(raw, str):
            raw = json.loads(raw)
        if not isinstance(raw, dict):
            raise ValueError("CloudTrail record must be a JSON object")

        event_name = raw.get("eventName", "Unknown")
        event_source = raw.get("eventSource", "aws")
        source_ip = raw.get("sourceIPAddress", None)
        user_identity = raw.get("userIdentity", {})
        user_name = user_identity.get("userName") or user_identity.get("arn", "unknown")
        error_code = raw.get("errorCode")

        severity = _AWSCloudTrailParser._SEVERITY_MAP.get(event_name, SeverityLevel.INFO)
        outcome = OutcomeType.FAILURE if error_code else OutcomeType.SUCCESS
        action = ActionType.AUTHENTICATE if "Login" in event_name else ActionType.EXECUTE

        return CanonicalEvent(
            source_type="aws_cloudtrail",
            event_category="cloud",
            event_type=event_name,
            severity=severity,
            action=action,
            outcome=outcome,
            message=f"{event_name} by {user_name} via {event_source}",
            signature_id=event_name,
            signature_name=event_source,
            network=NetworkInfo(src_ip=source_ip) if source_ip else None,
            source_entity=Entity(entity_type=EntityType.USER, identifier=user_name),
            metadata=EventMetadata(
                parser_name="aws_cloudtrail",
                raw_log=json.dumps(raw) if isinstance(raw, dict) else str(raw),
            ),
        )


class _GCPAuditParser:
    """Parse GCP Cloud Audit Log entries into CanonicalEvents."""

    _SEVERITY_MAP = {
        "compute.instances.delete": SeverityLevel.HIGH,
        "compute.firewalls.delete": SeverityLevel.CRITICAL,
        "iam.serviceAccounts.create": SeverityLevel.HIGH,
        "storage.buckets.delete": SeverityLevel.CRITICAL,
        "logging.sinks.delete": SeverityLevel.CRITICAL,
    }

    @staticmethod
    def parse(raw: Any) -> CanonicalEvent:
        if isinstance(raw, str):
            raw = json.loads(raw)
        if not isinstance(raw, dict):
            raise ValueError("GCP audit log must be a JSON object")

        proto = raw.get("protoPayload", raw)
        method_name = proto.get("methodName", "unknown")
        caller_ip = proto.get("requestMetadata", {}).get("callerIp")
        service_name = proto.get("serviceName", "gcp")
        auth_info = proto.get("authenticationInfo", {})
        principal = auth_info.get("principalEmail", "unknown")
        status = proto.get("status", {})
        error_code = status.get("code", 0) if isinstance(status, dict) else 0

        severity = _GCPAuditParser._SEVERITY_MAP.get(method_name, SeverityLevel.INFO)
        outcome = OutcomeType.FAILURE if error_code != 0 else OutcomeType.SUCCESS

        return CanonicalEvent(
            source_type="gcp_audit",
            event_category="cloud",
            event_type=method_name,
            severity=severity,
            action=ActionType.EXECUTE,
            outcome=outcome,
            message=f"{method_name} by {principal} on {service_name}",
            signature_id=method_name,
            signature_name=service_name,
            network=NetworkInfo(src_ip=caller_ip) if caller_ip else None,
            source_entity=Entity(entity_type=EntityType.USER, identifier=principal),
            metadata=EventMetadata(
                parser_name="gcp_audit",
                raw_log=json.dumps(raw) if isinstance(raw, dict) else str(raw),
            ),
        )


SyslogParser = _SyslogParser()
AWSCloudTrailParser = _AWSCloudTrailParser()
GCPAuditParser = _GCPAuditParser()


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
