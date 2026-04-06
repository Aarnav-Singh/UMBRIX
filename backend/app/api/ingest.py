"""Ingest API — the entry point for all processed events.

POST /api/v1/ingest receives a CanonicalEvent (either from
the Kafka consumer or direct API call), validates it, and
hands it to the 15-step processing pipeline.

All endpoints require a valid ``X-Ingest-API-Key`` header
matching ``settings.ingest_api_key``.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request, Depends, Header
from pydantic import BaseModel
import structlog

from app.config import settings
from app.schemas.canonical_event import CanonicalEvent
from app.dependencies import get_app_pipeline, get_app_ratelimiter
from app.services.pii_masking import mask_event
from app.services.ingestion.sentinel_connector import MicrosoftSentinelParser
from app.schemas.canonical_event import (
    ActionType, OutcomeType, SeverityLevel, NetworkInfo, Entity, EntityType, EventMetadata,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/ingest", tags=["ingest"])


# ── Ingest API Key Authentication ─────────────────────
async def require_ingest_key(
    x_ingest_api_key: str = Header(..., alias="X-Ingest-API-Key"),
) -> None:
    """Validate the ingest API key from the request header.

    Rejects requests when:
      - ``settings.ingest_api_key`` is not configured (fail-closed).
      - The header value does not match the configured key.
    """
    if not settings.ingest_api_key:
        logger.error("ingest_api_key_not_configured")
        raise HTTPException(
            status_code=503,
            detail="Ingest API key not configured on the server.",
        )
    if x_ingest_api_key != settings.ingest_api_key:
        logger.warning("ingest_auth_failed", provided_key_prefix=x_ingest_api_key[:4] + "***")
        raise HTTPException(status_code=401, detail="Invalid ingest API key.")


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
    _key: None = Depends(require_ingest_key),
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
    _key: None = Depends(require_ingest_key),
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
    _key: None = Depends(require_ingest_key),
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
    _key: None = Depends(require_ingest_key),
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


@router.post("/sentinel", status_code=202)
async def ingest_sentinel(
    log_entry: Dict[str, Any],
    request: Request,
    _key: None = Depends(require_ingest_key),
    limiter=Depends(get_app_ratelimiter),
) -> dict:
    """Ingest Microsoft Sentinel alerts/incidents via webhook."""
    await limiter.check_rate_limit(request, limit=50, window_seconds=60)
    pipeline = get_app_pipeline()
    try:
        ocsf_data = MicrosoftSentinelParser.parse(log_entry)
        if not ocsf_data:
            raise ValueError("Failed to parse Sentinel alert")
        
        # Determine severity enum (1-5 mapping)
        sev_id = ocsf_data.get("severity_id", 1)
        sev_enum = SeverityLevel.INFO
        for level in SeverityLevel:
            if level.value == sev_id:
                sev_enum = level
                break

        event = CanonicalEvent(
            source_type="azure_sentinel",
            event_category="security_finding",
            event_type=str(ocsf_data.get("activity_name", "Alert")),
            severity=sev_enum,
            action=ActionType.ALERT,
            outcome=OutcomeType.UNKNOWN,
            message=str(ocsf_data.get("message", "Sentinel Alert")),
            network=NetworkInfo(src_ip=ocsf_data.get("ip")) if "ip" in ocsf_data else None,
            source_entity=Entity(
                entity_type=EntityType.HOST if "hostname" in ocsf_data else EntityType.USER, 
                identifier=ocsf_data.get("hostname") or ocsf_data.get("user") or "unknown"
            ),
            metadata=EventMetadata(
                parser_name="microsoft_sentinel",
                raw_log=json.dumps(log_entry)
            ),
        )
        
        # Apply PII masking before pipeline processing
        masked_data = mask_event(event.model_dump())
        masked_event = CanonicalEvent(**masked_data)
        processed = await pipeline.process(masked_event)
        
        return {
            "status": "accepted",
            "event_id": processed.event_id,
            "meta_score": processed.ml_scores.meta_score,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("sentinel_ingest_failed")
        raise HTTPException(status_code=500, detail="Pipeline processing failed")


@router.post("/splunk-hec", status_code=202)
async def ingest_splunk_hec(
    req: Request,
    _key: None = Depends(require_ingest_key),
    limiter=Depends(get_app_ratelimiter),
) -> dict:
    """Ingest events from Splunk HTTP Event Collector (HEC)."""
    await limiter.check_rate_limit(req, limit=100, window_seconds=60)
    pipeline = get_app_pipeline()
    
    body = await req.body()
    try:
        # HEC accepts newline-delimited JSON or a JSON array
        if body.strip().startswith(b"["):
            events = json.loads(body)
        else:
            events = [json.loads(line) for line in body.splitlines() if line.strip()]
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid Splunk HEC payload format")
        
    processed_count = 0
    for splunk_event in events:
        try:
            event_content = splunk_event.get("event", {})
            msg = event_content if isinstance(event_content, str) else json.dumps(event_content)

            canonical = CanonicalEvent(
                source_type=splunk_event.get("sourcetype", "splunk_hec"),
                event_category="log",
                event_type="splunk_event",
                severity=SeverityLevel.INFO,
                action=ActionType.UNKNOWN,
                outcome=OutcomeType.UNKNOWN,
                message=msg,
                source_entity=Entity(entity_type=EntityType.HOST, identifier=splunk_event.get("host", "unknown")),
                metadata=EventMetadata(
                    parser_name="splunk_hec",
                    raw_log=json.dumps(splunk_event),
                ),
            )
            # Masking
            masked_data = mask_event(canonical.model_dump())
            # Process
            await pipeline.process(CanonicalEvent(**masked_data))
            processed_count += 1
        except Exception:
            logger.exception("splunk_hec_event_failed")
            
    return {"text": "Success", "code": 0, "processed": processed_count}
