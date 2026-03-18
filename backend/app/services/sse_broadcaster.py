"""SSE Broadcaster — real-time fan-out to dashboard clients.

Each connected browser tab gets its own asyncio.Queue.
When the pipeline finishes processing an event, it calls
``broadcast()`` which pushes to every subscriber queue.
"""
from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator

import structlog

logger = structlog.get_logger(__name__)


class SSEBroadcaster:
    """Manages SSE subscriber queues and broadcasts events."""

    def __init__(self) -> None:
        self._subscribers: dict[str, asyncio.Queue] = {}

    def subscribe(self, subscriber_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers[subscriber_id] = queue
        logger.info("sse_subscriber_added", subscriber_id=subscriber_id, total=len(self._subscribers))
        return queue

    def unsubscribe(self, subscriber_id: str) -> None:
        self._subscribers.pop(subscriber_id, None)
        logger.info("sse_subscriber_removed", subscriber_id=subscriber_id, total=len(self._subscribers))

    async def broadcast(self, event_data: dict) -> None:
        payload = json.dumps(event_data, default=str)
        dead: list[str] = []
        for sid, queue in self._subscribers.items():
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(sid)
                logger.warning("sse_queue_full_dropping", subscriber_id=sid)
        for sid in dead:
            self.unsubscribe(sid)

    async def event_stream(
        self,
        subscriber_id: str,
        heartbeat_seconds: int = 15,
    ) -> AsyncGenerator[str, None]:
        queue = self.subscribe(subscriber_id)
        try:
            while True:
                try:
                    payload = await asyncio.wait_for(
                        queue.get(), timeout=heartbeat_seconds
                    )
                    yield f"data: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            self.unsubscribe(subscriber_id)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Module-level singleton used by the SOAR engine and other services.
# main.py also creates its own instance for the lifespan scope; if you
# need the lifespan-scoped instance, use dependency injection via
# get_app_broadcaster().  This singleton is a safe fallback for modules
# that import at module-load time (e.g. engine.py).
broadcaster = SSEBroadcaster()
