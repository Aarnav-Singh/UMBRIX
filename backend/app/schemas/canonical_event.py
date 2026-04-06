"""CanonicalEvent — The Central Data Contract.

Every vendor parser, ML model, API endpoint, and database table
is defined relative to this schema. SCHEMA_VERSION lets us detect
drift between stored events and the current model definition.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

SCHEMA_VERSION = "2.0.0"


# ─── Enumerations ────────────────────────────────────────────────

class EntityType(str, Enum):
    IP = "ip"
    USER = "user"
    HOST = "host"
    DOMAIN = "domain"
    PROCESS = "process"
    FILE = "file"
    SERVICE = "service"


class ActionType(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    DROP = "drop"
    ALERT = "alert"
    DENY = "deny"
    AUTHENTICATE = "authenticate"
    EXECUTE = "execute"
    CONNECT = "connect"
    MODIFY = "modify"
    UNKNOWN = "unknown"


class OutcomeType(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ─── Nested Models ───────────────────────────────────────────────

class Entity(BaseModel):
    """An observed network / host / identity entity."""
    entity_type: EntityType
    identifier: str = Field(..., description="IP address, username, hostname, etc.")
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    asset_criticality: float = Field(
        default=0.5,
        ge=0.0, le=1.0,
        description="0.0 = low value, 1.0 = crown-jewel asset",
    )


class NetworkInfo(BaseModel):
    """Layer 3/4 network metadata."""
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0


class BehavioralDNA(BaseModel):
    """TLS/HTTP behavioral fingerprint for similarity matching."""
    ja3_hash: Optional[str] = None
    ja3s_hash: Optional[str] = None
    user_agent: Optional[str] = None
    uri_entropy: Optional[float] = None
    request_cadence_ms: Optional[float] = None
    payload_entropy: Optional[float] = None


class MitreMapping(BaseModel):
    """MITRE ATT&CK technique reference."""
    technique_id: str = Field(..., description="e.g. T1190")
    technique_name: str = Field(..., description="e.g. Exploit Public-Facing Application")
    tactic: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class MLScores(BaseModel):
    """Output of the 5-stream ML scoring pipeline."""
    ensemble_score: float = Field(default=0.0, ge=0.0, le=1.0)
    ensemble_label: Optional[str] = None
    vae_anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    hst_anomaly_score: float = Field(default=0.0, ge=0.0, le=1.0)
    temporal_score: float = Field(default=0.0, ge=0.0, le=1.0)
    adversarial_score: float = Field(default=0.0, ge=0.0, le=1.0)
    adversarial_timing_cov: Optional[float] = None
    meta_score: float = Field(default=0.0, ge=0.0, le=1.0)
    mitre_predictions: list[MitreMapping] = Field(default_factory=list)
    shap_top_features: dict[str, float] = Field(default_factory=dict)


class EventMetadata(BaseModel):
    """Processing metadata attached by the pipeline."""
    schema_version: str = SCHEMA_VERSION
    ingest_timestamp: datetime = Field(default_factory=datetime.utcnow)
    pipeline_duration_ms: Optional[float] = None
    tenant_id: str = "default"
    connector_id: Optional[str] = None
    raw_log: Optional[str] = None
    parser_name: Optional[str] = None


# ─── The Central Schema ─────────────────────────────────────────

class CanonicalEvent(BaseModel):
    """The universal event format every source normalizes into.

    This is the single most important data structure in the system.
    Every vendor parser produces one, every ML model consumes one,
    every ClickHouse row stores one, every SSE message broadcasts one.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Source classification
    source_type: str = Field(..., description="suricata | zeek | palo_alto | windows | crowdstrike | syslog")
    event_category: Optional[str] = None
    event_type: Optional[str] = None

    # What happened
    action: ActionType = ActionType.UNKNOWN
    outcome: OutcomeType = OutcomeType.UNKNOWN
    severity: SeverityLevel = SeverityLevel.INFO
    message: Optional[str] = None
    signature_id: Optional[str] = None
    signature_name: Optional[str] = None

    # Who / what was involved
    source_entity: Optional[Entity] = None
    destination_entity: Optional[Entity] = None
    network: Optional[NetworkInfo] = None
    behavioral_dna: Optional[BehavioralDNA] = None

    # ML pipeline outputs (populated during processing)
    ml_scores: MLScores = Field(default_factory=MLScores)

    # Campaign correlation
    campaign_id: Optional[str] = None
    posture_delta: float = 0.0

    # Compliance Automation
    compliance_tags: list[str] = Field(default_factory=list, description="Mapped control frameworks (e.g. SOC2:CC6.1, HIPAA:164.312)")

    # Metadata
    metadata: EventMetadata = Field(default_factory=EventMetadata)

    model_config = {"json_schema_extra": {"example": {
        "source_type": "suricata",
        "action": "alert",
        "severity": "high",
        "message": "ET MALWARE CobaltStrike Beacon Activity",
        "signature_id": "2024217",
        "source_entity": {
            "entity_type": "ip",
            "identifier": "10.0.1.45",
            "asset_criticality": 0.3,
        },
        "destination_entity": {
            "entity_type": "ip",
            "identifier": "198.51.100.22",
        },
        "network": {
            "src_ip": "10.0.1.45",
            "dst_ip": "198.51.100.22",
            "dst_port": 443,
            "protocol": "tcp",
        },
    }}}
