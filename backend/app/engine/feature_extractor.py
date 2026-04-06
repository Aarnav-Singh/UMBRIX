"""76-Dimensional Feature Extractor.

Transforms a CanonicalEvent + Redis entity history into
the tabular feature vector consumed by the supervised ensemble
(Stream 1) and the Half-Space Trees (Stream 3).
"""
from __future__ import annotations

from typing import Optional

from app.schemas.canonical_event import CanonicalEvent


def extract_features(event: CanonicalEvent, entity_state: Optional[dict] = None) -> list[float]:
    """Build the 76-dimensional feature vector from a CanonicalEvent.

    Features are grouped into 5 blocks:
        [0-15]  Network layer features
        [16-31] Entity behavioral features
        [32-47] Temporal features
        [48-63] Payload / signature features
        [64-75] Contextual features
    """
    net = event.network
    src = event.source_entity
    dst = event.destination_entity
    state = entity_state or {}

    # ── Network features (0–15) ──────────────────────────
    features: list[float] = [
        float(net.src_port or 0),
        float(net.dst_port or 0),
        float(net.bytes_in),
        float(net.bytes_out),
        float(net.packets_in),
        float(net.packets_out),
        _bytes_per_packet(net.bytes_in, net.packets_in),
        _bytes_per_packet(net.bytes_out, net.packets_out),
        float(net.bytes_in + net.bytes_out),
        float(net.packets_in + net.packets_out),
        _ratio(net.bytes_in, net.bytes_out),
        _ratio(net.packets_in, net.packets_out),
        1.0 if (net.protocol or "").lower() == "tcp" else 0.0,
        1.0 if (net.protocol or "").lower() == "udp" else 0.0,
        1.0 if (net.dst_port or 0) < 1024 else 0.0,
        1.0 if (net.dst_port or 0) in {22, 23, 3389, 5900} else 0.0,
    ] if net else [0.0] * 16

    # ── Entity behavioral features (16–31) ───────────────
    features.extend([
        src.asset_criticality if src else 0.5,
        dst.asset_criticality if dst else 0.5,
        state.get("p_recon", 0.0),
        state.get("p_cred_stuffing", 0.0),
        state.get("p_lateral", 0.0),
        state.get("p_exfil", 0.0),
        state.get("p_persistence", 0.0),
        float(state.get("event_count", 0)),
        1.0 if src and src.geo_country and src.geo_country != "US" else 0.0,
        1.0 if dst and dst.geo_country and dst.geo_country != "US" else 0.0,
        _entity_type_encoding(src.entity_type.value if src else "ip"),
        _entity_type_encoding(dst.entity_type.value if dst else "ip"),
        0.0, 0.0, 0.0, 0.0,  # Reserved
    ])

    # ── Temporal features (32–47) ────────────────────────
    hour = event.timestamp.hour
    now_ts = event.timestamp.timestamp()
    last_seen = state.get("last_seen", now_ts)
    inter_event_gap = max(0.0, now_ts - last_seen)
    
    if inter_event_gap > 3600:
        events_1h = 0
        events_5m = 0
        unique_ips = 0
        unique_ports = 0
    elif inter_event_gap > 300:
        events_5m = 0
        events_1h = state.get("events_1h", 0)
        unique_ips = len(state.get("unique_dst_ips_1h", []))
        unique_ports = len(state.get("unique_dst_ports_1h", []))
    else:
        events_5m = state.get("events_5m", 0)
        events_1h = state.get("events_1h", 0)
        unique_ips = len(state.get("unique_dst_ips_1h", []))
        unique_ports = len(state.get("unique_dst_ports_1h", []))

    features.extend([
        float(hour),
        1.0 if hour < 6 or hour > 22 else 0.0,  # Off-hours
        1.0 if event.timestamp.weekday() >= 5 else 0.0,  # Weekend
        float(inter_event_gap),  # inter-event gap (requires history)
        float(events_5m),  # events in last 5 min
        float(events_1h),  # events in last 1 hour
        float(unique_ips),  # unique dst IPs in last hour
        float(unique_ports),  # unique dst ports in last hour
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # Reserved temporal
    ])

    # ── Payload / signature features (48–63) ─────────────
    dna = event.behavioral_dna
    features.extend([
        1.0 if event.signature_id else 0.0,
        _severity_encoding(event.severity.value),
        _action_encoding(event.action.value),
        dna.uri_entropy if dna and dna.uri_entropy else 0.0,
        dna.payload_entropy if dna and dna.payload_entropy else 0.0,
        dna.request_cadence_ms if dna and dna.request_cadence_ms else 0.0,
        1.0 if dna and dna.ja3_hash else 0.0,
        len(event.message or "") / 500.0,  # Normalized message length
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # Reserved payload
    ])

    # ── Contextual features (64–75) ──────────────────────
    features.extend([
        _source_type_encoding(event.source_type),
        1.0 if event.campaign_id else 0.0,
        event.posture_delta,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # Reserved
    ])

    assert len(features) == 76, f"Feature vector dimension mismatch: {len(features)}"
    return features


# ── Helpers ──────────────────────────────────────────────

def _bytes_per_packet(byte_count: int, packet_count: int) -> float:
    return byte_count / packet_count if packet_count > 0 else 0.0

def _ratio(a: int, b: int) -> float:
    return a / (a + b) if (a + b) > 0 else 0.5

def _entity_type_encoding(entity_type: str) -> float:
    mapping = {"ip": 0.0, "user": 0.2, "host": 0.4, "domain": 0.6, "process": 0.8, "file": 1.0}
    return mapping.get(entity_type, 0.0)

def _severity_encoding(severity: str) -> float:
    mapping = {"info": 0.0, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
    return mapping.get(severity, 0.0)

def _action_encoding(action: str) -> float:
    mapping = {"allow": 0.0, "alert": 0.5, "block": 0.75, "drop": 0.85, "deny": 1.0}
    return mapping.get(action, 0.25)

def _source_type_encoding(source_type: str) -> float:
    mapping = {"suricata": 0.0, "zeek": 0.2, "palo_alto": 0.4, "windows": 0.6, "crowdstrike": 0.8, "syslog": 1.0}
    return mapping.get(source_type, 0.5)
