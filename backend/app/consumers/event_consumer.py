"""Kafka Event Consumer — the system's loading dock.

Polls Kafka topics, routes raw messages to the correct connector
parser, and processes the resulting CanonicalEvent through the pipeline.
Failed messages are routed to the dead letter queue.
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
except ImportError:
    AIOKafkaConsumer = None  # type: ignore[misc,assignment]
    AIOKafkaProducer = None  # type: ignore[misc,assignment]

from app.config import settings
from app.connectors.base import BaseParser
from app.connectors.suricata import SuricataParser
from app.connectors.zeek import ZeekParser
from app.connectors.windows_event import WindowsEventParser
from app.connectors.generic_syslog import GenericSyslogParser
from app.connectors.palo_alto import PaloAltoParser
from app.connectors.crowdstrike import CrowdStrikeParser
from app.services.pipeline import PipelineService

import structlog

logger = structlog.get_logger(__name__)

# ── Topic → Parser registry ─────────────────────────────

PARSER_REGISTRY: dict[str, BaseParser] = {
    "sentinel.suricata": SuricataParser(),
    "sentinel.zeek": ZeekParser(),
    "sentinel.windows": WindowsEventParser(),
    "sentinel.syslog": GenericSyslogParser(),
    "sentinel.palo_alto": PaloAltoParser(),
    "sentinel.crowdstrike": CrowdStrikeParser(),
}


class EventConsumer:
    """Async Kafka consumer that feeds the processing pipeline."""

    def __init__(self, pipeline: PipelineService) -> None:
        self._pipeline = pipeline
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._dlq_producer: Optional[AIOKafkaProducer] = None
        self._running = False

    async def start(self) -> None:
        self._consumer = AIOKafkaConsumer(
            *settings.kafka_topics,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.kafka_consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=False,
            value_deserializer=lambda v: v.decode("utf-8"),
        )
        self._dlq_producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )
        await self._consumer.start()
        await self._dlq_producer.start()
        self._running = True
        logger.info(
            "kafka_consumer_started",
            topics=settings.kafka_topics,
            group=settings.kafka_consumer_group,
        )

    async def stop(self) -> None:
        self._running = False
        if self._consumer:
            await self._consumer.stop()
        if self._dlq_producer:
            await self._dlq_producer.stop()
        logger.info("kafka_consumer_stopped")

    async def run(self) -> None:
        """Main consumer loop — poll, parse, process."""
        assert self._consumer is not None, "Call start() first"

        async for message in self._consumer:
            if not self._running:
                break

            topic = message.topic
            raw_log = message.value
            parser = PARSER_REGISTRY.get(topic)

            if parser is None:
                logger.warning("no_parser_for_topic", topic=topic)
                await self._send_to_dlq(topic, raw_log, "no_parser_registered")
                continue

            try:
                event = parser.parse(raw_log)
                await self._pipeline.process(event)
                await self._consumer.commit()
            except ValueError as exc:
                logger.warning("parse_failed", topic=topic, error=str(exc))
                await self._send_to_dlq(topic, raw_log, str(exc))
            except Exception as exc:
                logger.exception("pipeline_failed", topic=topic, error=str(exc))
                await self._send_to_dlq(topic, raw_log, str(exc))

    async def _send_to_dlq(self, topic: str, raw_log: str, reason: str) -> None:
        if self._dlq_producer:
            await self._dlq_producer.send(
                settings.kafka_dlq_topic,
                value={
                    "original_topic": topic,
                    "raw_log": raw_log[:10000],
                    "error_reason": reason,
                },
            )
