"""Simulation API — generates realistic security events for development.

POST /api/v1/simulate/start  — begins continuous event generation
POST /api/v1/simulate/stop   — stops generation
POST /api/v1/simulate/burst  — injects a burst of N events immediately
"""
from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.auth import AuditLogger
from app.dependencies import get_app_pipeline
from app.schemas.canonical_event import (
    ActionType,
    CanonicalEvent,
    Entity,
    EntityType,
    EventMetadata,
    NetworkInfo,
    OutcomeType,
    SeverityLevel,
)

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/simulate", tags=["simulation"])

# ── Simulation state ────────────────────────────────────
_running = False
_task: asyncio.Task | None = None

# ── Realistic event templates ────────────────────────────

_SCENARIOS = [
    {
        "source": "suricata", "msg": "ET MALWARE CobaltStrike Beacon Activity",
        "severity": SeverityLevel.CRITICAL, "action": ActionType.ALERT,
        "category": "malware", "sig_id": "2024217",
    },
    {
        "source": "suricata", "msg": "ET SCAN Nmap -sV port probe",
        "severity": SeverityLevel.HIGH, "action": ActionType.ALERT,
        "category": "scan", "sig_id": "2010936",
    },
    {
        "source": "zeek", "msg": "SSH brute force attempt detected",
        "severity": SeverityLevel.HIGH, "action": ActionType.BLOCK,
        "category": "auth", "sig_id": None,
    },
    {
        "source": "windows", "msg": "Event 4625: Failed logon for admin account",
        "severity": SeverityLevel.MEDIUM, "action": ActionType.AUTHENTICATE,
        "category": "security", "sig_id": "4625",
    },
    {
        "source": "windows", "msg": "Event 4688: PowerShell.exe spawned by cmd.exe",
        "severity": SeverityLevel.HIGH, "action": ActionType.EXECUTE,
        "category": "security", "sig_id": "4688",
    },
    {
        "source": "syslog", "msg": "Firewall denied outbound connection to known C2 IP",
        "severity": SeverityLevel.CRITICAL, "action": ActionType.DENY,
        "category": "network", "sig_id": None,
    },
    {
        "source": "suricata", "msg": "DNS query to suspicious domain detected",
        "severity": SeverityLevel.MEDIUM, "action": ActionType.ALERT,
        "category": "dns", "sig_id": "2027000",
    },
    {
        "source": "zeek", "msg": "Large data transfer to external IP (2.4 GB)",
        "severity": SeverityLevel.HIGH, "action": ActionType.ALLOW,
        "category": "exfiltration", "sig_id": None,
    },
    {
        "source": "windows", "msg": "Event 7045: New service installed (persistence)",
        "severity": SeverityLevel.CRITICAL, "action": ActionType.EXECUTE,
        "category": "security", "sig_id": "7045",
    },
    {
        "source": "suricata", "msg": "TLS connection to self-signed certificate",
        "severity": SeverityLevel.LOW, "action": ActionType.ALLOW,
        "category": "tls", "sig_id": "2025100",
    },
]

_SRC_IPS = ["10.0.1.45", "10.0.2.88", "192.168.1.100", "10.0.5.22", "172.16.0.50"]
_DST_IPS = ["198.51.100.22", "203.0.113.44", "104.26.8.17", "185.220.101.33", "93.184.216.34"]
_USERS = ["admin", "jdoe", "msmith", "svc_backup", "root"]


def _generate_event() -> CanonicalEvent:
    """Generate a single realistic security event."""
    scenario = random.choice(_SCENARIOS)
    src_ip = random.choice(_SRC_IPS)
    dst_ip = random.choice(_DST_IPS)

    
    event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        source_type=scenario["source"],
        event_category=scenario["category"],
        event_type=scenario["category"],
        action=scenario["action"],
        outcome=OutcomeType.SUCCESS if scenario["action"] != ActionType.DENY else OutcomeType.FAILURE,
        severity=scenario["severity"],
        message=scenario["msg"],
        signature_id=scenario["sig_id"],
        source_entity=Entity(
            entity_type=EntityType.IP,
            identifier=src_ip,
        ),
        destination_entity=Entity(
            entity_type=EntityType.IP,
            identifier=dst_ip,
        ),
        network=NetworkInfo(
            src_ip=src_ip,
            src_port=random.randint(30000, 65000),
            dst_ip=dst_ip,
            dst_port=random.choice([22, 80, 443, 445, 3389, 8080, 8443]),
            protocol=random.choice(["TCP", "UDP"]),
            bytes_in=random.randint(64, 500000),
            bytes_out=random.randint(64, 500000),
            packets_in=random.randint(1, 1000),
            packets_out=random.randint(1, 1000),
        ),
        metadata=EventMetadata(
            parser_name=f"{scenario['source']}_simulator",
        ),
    )
    
    # ML scores will be computed by the pipeline — no manual override needed
    return event


async def _simulation_loop(interval_seconds: float = 2.0):
    """Continuously generate and process events."""
    global _running
    pipeline = get_app_pipeline()
    count = 0

    while _running:
        try:
            event = _generate_event()
            await pipeline.process(event)
            count += 1
            if count % 10 == 0:
                logger.info("simulation_events_processed", count=count)
        except Exception as exc:
            logger.warning("simulation_event_failed", error=str(exc))

        await asyncio.sleep(interval_seconds)


_optional_bearer = HTTPBearer(auto_error=False)


async def _optional_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(_optional_bearer),
) -> dict | None:
    """Extract JWT claims if present, else return None (no auth required)."""
    if credentials is None:
        return None
    try:
        from app.middleware.auth import decode_token
        return decode_token(credentials.credentials)
    except Exception:
        return None


@router.post("/start")
async def start_simulation(
    interval: float = 2.0,
    request: Request = None,
    claims: dict | None = Depends(_optional_claims),
) -> dict:
    """Start continuous event generation."""
    if claims:
        AuditLogger.log("simulation_started", request=request, claims=claims, detail=f"interval={interval}")
    global _running, _task

    if _running:
        return {"status": "already_running"}

    _running = True
    _task = asyncio.create_task(_simulation_loop(interval))
    logger.info("simulation_started", interval=interval)
    return {"status": "started", "interval_seconds": interval}


@router.post("/stop")
async def stop_simulation(
    request: Request = None,
    claims: dict | None = Depends(_optional_claims),
) -> dict:
    """Stop continuous event generation."""
    if claims:
        AuditLogger.log("simulation_stopped", request=request, claims=claims)
    global _running, _task

    _running = False
    if _task:
        _task.cancel()
        _task = None

    logger.info("simulation_stopped")
    return {"status": "stopped"}


@router.post("/burst")
async def burst_events(
    count: int = 10,
    request: Request = None,
    claims: dict | None = Depends(_optional_claims),
) -> dict:
    """Inject a burst of N events immediately."""
    if claims:
        AuditLogger.log("simulation_burst", request=request, claims=claims, detail=f"count={count}")
    pipeline = get_app_pipeline()
    processed = 0

    for _ in range(min(count, 100)):
        try:
            event = _generate_event()
            await pipeline.process(event)
            processed += 1
        except Exception as exc:
            logger.warning("burst_event_failed", error=str(exc))

    return {"status": "burst_complete", "events_processed": processed}
