"""In-Memory ClickHouse fallback — used when real ClickHouse is unavailable.

Stores events in a deque for the dashboard to query. No persistence.
Transparent drop-in for the real ClickHouseRepository interface.
"""
from __future__ import annotations

from collections import deque

from app.schemas.canonical_event import CanonicalEvent

import structlog

logger = structlog.get_logger(__name__)


class InMemoryClickHouse:
    """In-memory event store with the same interface as ClickHouseRepository."""

    def __init__(self, max_events: int = 5000) -> None:
        self._events: deque[dict] = deque(maxlen=max_events)
        self._connected = False

    async def connect(self) -> None:
        self._connected = True
        logger.info("inmemory_clickhouse_started", max_events=self._events.maxlen)

    async def close(self) -> None:
        self._connected = False

    async def insert_event(self, event: CanonicalEvent) -> None:
        net = event.network
        row = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "source_type": event.source_type,
            "event_category": event.event_category,
            "event_type": event.event_type,
            "action": event.action.value,
            "outcome": event.outcome.value,
            "severity": event.severity.value,
            "message": event.message,
            "signature_id": event.signature_id,
            "src_ip": net.src_ip if net else None,
            "src_port": net.src_port if net else None,
            "dst_ip": net.dst_ip if net else None,
            "dst_port": net.dst_port if net else None,
            "protocol": net.protocol if net else None,
            "bytes_in": net.bytes_in if net else 0,
            "bytes_out": net.bytes_out if net else 0,
            "ensemble_score": event.ml_scores.ensemble_score,
            "vae_score": event.ml_scores.vae_anomaly_score,
            "hst_score": event.ml_scores.hst_anomaly_score,
            "temporal_score": event.ml_scores.temporal_score,
            "adversarial_score": event.ml_scores.adversarial_score,
            "meta_score": event.ml_scores.meta_score,
            "campaign_id": event.campaign_id,
            "posture_delta": event.posture_delta,
            "tenant_id": event.metadata.tenant_id,
        }
        self._events.appendleft(row)

    async def query_events(
        self,
        tenant_id: str = "default",
        limit: int = 100,
        min_score: float = 0.0,
    ) -> list[dict]:
        results = []
        for e in self._events:
            if e.get("tenant_id", "default") == tenant_id:
                if e.get("meta_score", 0) >= min_score:
                    results.append(e)
                    if len(results) >= limit:
                        break
        return results

    async def get_event_count(self, tenant_id: str = "default") -> int:
        return sum(1 for e in self._events if e.get("tenant_id", "default") == tenant_id)

    @property
    def all_events(self) -> list[dict]:
        return list(self._events)
