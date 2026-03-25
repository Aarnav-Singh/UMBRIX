"""ClickHouse repository — analytical event storage.

Append-only columnar store for CanonicalEvents, posture snapshots,
and campaign records. Optimized for time-range + aggregate queries.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta

import clickhouse_connect
from clickhouse_connect.driver.client import Client as CHClient

from app.config import settings
from app.schemas.canonical_event import CanonicalEvent

import structlog

logger = structlog.get_logger(__name__)

# ── Table DDL ────────────────────────────────────────────────────

EVENTS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS events (
    event_id         String,
    timestamp        DateTime64(3),
    source_type      LowCardinality(String),
    event_category   Nullable(String),
    event_type       Nullable(String),
    action           LowCardinality(String),
    outcome          LowCardinality(String),
    severity         LowCardinality(String),
    message          Nullable(String),
    signature_id     Nullable(String),
    signature_name   Nullable(String),

    src_ip           Nullable(String),
    src_port         Nullable(UInt16),
    dst_ip           Nullable(String),
    dst_port         Nullable(UInt16),
    protocol         Nullable(String),
    bytes_in         UInt64 DEFAULT 0,
    bytes_out        UInt64 DEFAULT 0,

    ensemble_score   Float32 DEFAULT 0.0,
    vae_score        Float32 DEFAULT 0.0,
    hst_score        Float32 DEFAULT 0.0,
    temporal_score   Float32 DEFAULT 0.0,
    adversarial_score Float32 DEFAULT 0.0,
    meta_score       Float32 DEFAULT 0.0,

    campaign_id      Nullable(String),
    posture_delta    Float32 DEFAULT 0.0,

    tenant_id        LowCardinality(String),
    connector_id     Nullable(String),
    raw_log          Nullable(String),
    parser_name      Nullable(String),

    ingest_timestamp DateTime64(3) DEFAULT now64(3)
) ENGINE = MergeTree()
ORDER BY (tenant_id, timestamp, source_type)
PARTITION BY toYYYYMM(timestamp)
TTL timestamp + INTERVAL 90 DAY
"""

DISTRIBUTED_EVENTS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS events_distributed AS events
ENGINE = Distributed('sf_cluster', currentDatabase(), events, rand())
"""

_INSERT_COLUMNS = [
    "event_id", "timestamp", "source_type", "event_category",
    "event_type", "action", "outcome", "severity", "message",
    "signature_id", "signature_name", "src_ip", "src_port",
    "dst_ip", "dst_port", "protocol", "bytes_in", "bytes_out",
    "ensemble_score", "vae_score", "hst_score", "temporal_score",
    "adversarial_score", "meta_score", "campaign_id", "posture_delta",
    "tenant_id", "connector_id", "raw_log", "parser_name",
]


class ClickHouseRepository:
    """Data access layer for ClickHouse.

    Enterprise-grade batched ingestion:
      - Events are buffered in memory and flushed to ClickHouse in bulk
        every BATCH_INTERVAL_S or when the buffer reaches BATCH_SIZE.
      - Per @cc-skill-clickhouse-io: "Avoid small frequent inserts — batch instead."
      - Retry with exponential back-off on transient flush failures
        per @error-handling-patterns.
    """

    BATCH_SIZE: int = 500
    BATCH_INTERVAL_S: float = 0.2  # 200 ms
    MAX_FLUSH_RETRIES: int = 3

    def __init__(self) -> None:
        self._client: CHClient | None = None
        self._fallback_events: list[dict] = []

        # Batch buffer (protected by asyncio.Lock for coroutine safety)
        self._buffer: list[list] = []
        self._buffer_lock = asyncio.Lock()
        self._flush_task: asyncio.Task | None = None
        self._stopping = False

        # Metrics
        self._total_flushed: int = 0
        self._flush_errors: int = 0

    # ── Lifecycle ──────────────────────────────────────────

    async def connect(self) -> None:
        def _sync_connect():
            client = clickhouse_connect.get_client(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                database=settings.clickhouse_database,
                username=settings.clickhouse_user,
                password=settings.clickhouse_password,
            )
            client.command(EVENTS_TABLE_DDL)
            try:
                # Set up the federated 'Distributed' table over the local tables
                client.command(DISTRIBUTED_EVENTS_TABLE_DDL)
            except Exception as e:
                logger.warning("clickhouse_distributed_table_creation_failed_fallback_to_local", error=str(e))
                
            return client

        self._client = await asyncio.to_thread(_sync_connect)
        logger.info("clickhouse_connected", database=settings.clickhouse_database)

        # Start background flush loop
        self._stopping = False
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("clickhouse_batch_worker_started",
                     batch_size=self.BATCH_SIZE,
                     interval_ms=int(self.BATCH_INTERVAL_S * 1000))

    async def close(self) -> None:
        """Gracefully drain the buffer before shutting down."""
        await self.flush_and_stop()
        if self._client:
            self._client.close()

    async def flush_and_stop(self) -> None:
        """Signal the flush loop to stop and drain remaining events."""
        self._stopping = True
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        # Final drain
        await self._flush_buffer()
        logger.info("clickhouse_batch_worker_stopped",
                     total_flushed=self._total_flushed,
                     flush_errors=self._flush_errors)

    # ── Background Flush Loop ─────────────────────────────

    async def _flush_loop(self) -> None:
        """Periodically flush buffered rows to ClickHouse."""
        try:
            while not self._stopping:
                await asyncio.sleep(self.BATCH_INTERVAL_S)
                await self._flush_buffer()
        except asyncio.CancelledError:
            pass  # Expected on shutdown

    async def _flush_buffer(self) -> None:
        """Flush the current buffer to ClickHouse with retry."""
        async with self._buffer_lock:
            if not self._buffer:
                return
            batch = self._buffer.copy()
            self._buffer.clear()

        if not self._client:
            return

        # Retry with exponential back-off (@error-handling-patterns)
        for attempt in range(self.MAX_FLUSH_RETRIES):
            try:
                await asyncio.to_thread(
                    self._client.insert,
                    "events",
                    batch,
                    column_names=_INSERT_COLUMNS,
                )
                self._total_flushed += len(batch)
                logger.debug("clickhouse_batch_flushed", rows=len(batch))
                return
            except Exception as exc:
                self._flush_errors += 1
                wait = (2 ** attempt) * 0.1  # 100ms, 200ms, 400ms
                logger.warning(
                    "clickhouse_flush_retry",
                    attempt=attempt + 1,
                    max_retries=self.MAX_FLUSH_RETRIES,
                    error=str(exc),
                    backoff_s=wait,
                )
                if attempt < self.MAX_FLUSH_RETRIES - 1:
                    await asyncio.sleep(wait)

        # All retries exhausted — re-enqueue to avoid data loss
        async with self._buffer_lock:
            self._buffer = batch + self._buffer
        logger.error("clickhouse_flush_failed_requeued", rows=len(batch))

    # ── Public Properties ─────────────────────────────────

    @property
    def client(self) -> CHClient:
        if not self._client:
            raise RuntimeError("ClickHouse client not initialized. Call connect() first.")
        return self._client

    @property
    def pending_count(self) -> int:
        """Number of events waiting in the batch buffer."""
        return len(self._buffer)

    # ── Insert (Batched) ──────────────────────────────────

    def _event_to_row(self, event: CanonicalEvent) -> list:
        """Convert a CanonicalEvent to a flat row list for bulk insert."""
        net = event.network
        return [
            event.event_id,
            event.timestamp,
            event.source_type,
            event.event_category,
            event.event_type,
            event.action.value,
            event.outcome.value,
            event.severity.value,
            event.message,
            event.signature_id,
            event.signature_name,
            net.src_ip if net else None,
            net.src_port if net else None,
            net.dst_ip if net else None,
            net.dst_port if net else None,
            net.protocol if net else None,
            net.bytes_in if net else 0,
            net.bytes_out if net else 0,
            event.ml_scores.ensemble_score,
            event.ml_scores.vae_anomaly_score,
            event.ml_scores.hst_anomaly_score,
            event.ml_scores.temporal_score,
            event.ml_scores.adversarial_score,
            event.ml_scores.meta_score,
            event.campaign_id,
            event.posture_delta,
            event.metadata.tenant_id,
            event.metadata.connector_id,
            event.metadata.raw_log,
            event.metadata.parser_name,
        ]

    def _event_to_dict(self, event: CanonicalEvent) -> dict:
        """Convert to dict for in-memory fallback storage."""
        net = event.network
        return {
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
            "signature_name": event.signature_name,
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
            "connector_id": event.metadata.connector_id,
            "raw_log": event.metadata.raw_log,
            "parser_name": event.metadata.parser_name,
        }

    async def insert_event(self, event: CanonicalEvent) -> None:
        """Append event to the batch buffer (non-blocking).

        The background flush loop will persist it to ClickHouse
        within BATCH_INTERVAL_S or once BATCH_SIZE is reached.
        """
        if not self._client:
            logger.debug("clickhouse_fallback_insert", event_id=event.event_id)
            self._fallback_events.append(self._event_to_dict(event))
            return

        async with self._buffer_lock:
            self._buffer.append(self._event_to_row(event))
            should_flush = len(self._buffer) >= self.BATCH_SIZE

        # Eagerly flush when buffer is full (don't wait for timer)
        if should_flush:
            await self._flush_buffer()

    # ── Query Methods (unchanged) ─────────────────────────

    async def query_events(
        self,
        tenant_id: str = "default",
        limit: int = 100,
        min_score: float = 0.0,
    ) -> list[dict]:
        query = """
            SELECT * FROM events
            WHERE tenant_id = {tenant_id:String}
              AND meta_score >= {min_score:Float32}
            ORDER BY timestamp DESC
            LIMIT {limit:UInt32}
        """
        if not self._client:
            filtered = [
                e for e in self._fallback_events
                if e["tenant_id"] == tenant_id and e["meta_score"] >= min_score
            ]
            filtered.sort(key=lambda x: x["timestamp"], reverse=True)
            return filtered[:limit]

        result = await asyncio.to_thread(
            self.client.query,
            query,
            parameters={
                "tenant_id": tenant_id,
                "min_score": min_score,
                "limit": limit,
            },
        )
        return [
            dict(zip(result.column_names, row))
            for row in result.result_rows
        ]

    async def query_events_paginated(
        self,
        tenant_id: str = "default",
        limit: int = 20,
        offset: int = 0,
        min_score: float = 0.0,
        campaign_id: str | None = None,
        source_type: str | None = None,
    ) -> tuple[list[dict], int]:
        """Return (events, total_count) with full filtering support."""
        where = ["tenant_id = {tenant_id:String}"]
        params: dict = {"tenant_id": tenant_id, "limit": limit, "offset": offset}

        if min_score > 0:
            where.append("meta_score >= {min_score:Float32}")
            params["min_score"] = min_score
        if campaign_id:
            where.append("campaign_id = {campaign_id:String}")
            params["campaign_id"] = campaign_id
        if source_type:
            where.append("source_type = {source_type:String}")
            params["source_type"] = source_type

        where_clause = " AND ".join(where)

        # SECURITY NOTE — this f-string is safe.
        # `where` only ever contains ClickHouse *parameter placeholder strings*
        # such as "tenant_id = {tenant_id:String}" or "campaign_id = {campaign_id:String}".
        # Raw user values are NEVER interpolated here; they are passed separately
        # in the `parameters={}` dict below and sanitised by the ClickHouse client
        # driver before the query is sent over the wire.
        # DO NOT modify this pattern without also replacing the params dict.

        if not self._client:
            filtered = self._fallback_events
            filtered = [e for e in filtered if e.get("tenant_id", "default") == tenant_id]
            if min_score > 0:
                filtered = [e for e in filtered if e.get("meta_score", 0) >= min_score]
            if campaign_id:
                filtered = [e for e in filtered if e.get("campaign_id") == campaign_id]
            if source_type:
                filtered = [e for e in filtered if e.get("source_type") == source_type]
            filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            total = len(filtered)
            return filtered[offset: offset + limit], total

        count_q = f"SELECT count() FROM events WHERE {where_clause}"
        count_result = await asyncio.to_thread(
            self.client.query, count_q, parameters=params,
        )
        total = count_result.result_rows[0][0]

        data_q = f"""
            SELECT * FROM events
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT {{limit:UInt32}} OFFSET {{offset:UInt32}}
        """
        result = await asyncio.to_thread(
            self.client.query, data_q, parameters=params,
        )
        rows = [dict(zip(result.column_names, row)) for row in result.result_rows]
        return rows, total

    async def get_event_count(self, tenant_id: str = "default") -> int:
        if not self._client:
            return len([e for e in self._fallback_events if e["tenant_id"] == tenant_id])

        result = await asyncio.to_thread(
            self.client.query,
            "SELECT count() FROM events WHERE tenant_id = {tenant_id:String}",
            parameters={"tenant_id": tenant_id},
        )
        return result.result_rows[0][0]

    async def query_severity_distribution(
        self, tenant_id: str = "default"
    ) -> dict[str, int]:
        """Return event counts grouped by severity."""
        if not self._client:
            dist: dict[str, int] = {}
            for e in self._fallback_events:
                if e.get("tenant_id", "default") == tenant_id:
                    sev = e.get("severity", "info")
                    dist[sev] = dist.get(sev, 0) + 1
            return dist

        result = await asyncio.to_thread(
            self.client.query,
            """SELECT severity, count() AS cnt FROM events
               WHERE tenant_id = {tenant_id:String}
               GROUP BY severity""",
            parameters={"tenant_id": tenant_id},
        )
        return {row[0]: row[1] for row in result.result_rows}

    # ── RAG Integration ───────────────────────────────────

    async def search_similar_events(
        self,
        tenant_id: str,
        query: str,
        limit: int = 10,
    ) -> list[dict]:
        """Native RAG: Search historical events by text/payload matching."""
        if not self._client:
            # Fallback for tests
            q = query.lower()
            filtered = [
                e for e in self._fallback_events
                if e.get("tenant_id", "default") == tenant_id
                and (q in str(e.get("message", "")).lower() or
                     q in str(e.get("raw_log", "")).lower() or
                     q in str(e.get("src_ip", "")).lower() or
                     q in str(e.get("dst_ip", "")).lower())
            ]
            filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            return filtered[:limit]

        sql = """
            SELECT * FROM events
            WHERE tenant_id = {tenant_id:String}
              AND (
                  positionCaseInsensitive(coalesce(message, ''), {query:String}) > 0
                  OR positionCaseInsensitive(coalesce(raw_log, ''), {query:String}) > 0
                  OR positionCaseInsensitive(coalesce(src_ip, ''), {query:String}) > 0
                  OR positionCaseInsensitive(coalesce(dst_ip, ''), {query:String}) > 0
                  OR positionCaseInsensitive(action, {query:String}) > 0
              )
            ORDER BY timestamp DESC
            LIMIT {limit:UInt32}
        """
        result = await asyncio.to_thread(
            self.client.query,
            sql,
            parameters={
                "tenant_id": tenant_id,
                "query": query,
                "limit": limit,
            },
        )
        return [
            dict(zip(result.column_names, row))
            for row in result.result_rows
        ]

    async def query_posture_history(
        self,
        tenant_id: str,
        days: int = 30,
    ) -> list[dict]:
        """Aggregate posture history from events data."""
        if not self._client:
            # Fallback for tests
            now = datetime.now(timezone.utc)
            history = []
            for i in range(days):
                date = (now - timedelta(days=days - i - 1)).strftime("%Y-%m-%d")
                history.append({
                    "day": date,
                    "avg_score": 0.0,
                    "high_threat_events": 0,
                    "total_events": 0
                })
            return history

        sql = """
            SELECT
                toDate(timestamp) AS day,
                avg(meta_score) AS avg_score,
                countIf(meta_score > 0.7) AS high_threat_events,
                count() AS total_events
            FROM events
            WHERE tenant_id = {tenant_id:String}
              AND timestamp >= now() - INTERVAL {days:Int32} DAY
            GROUP BY day
            ORDER BY day ASC
        """
        result = await asyncio.to_thread(
            self.client.query,
            sql,
            parameters={
                "tenant_id": tenant_id,
                "days": days,
            },
        )
        return [
            dict(zip(result.column_names, row))
            for row in result.result_rows
        ]
