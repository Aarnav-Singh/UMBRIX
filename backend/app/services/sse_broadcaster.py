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
        # Nested dict: {tenant_id: {subscriber_id: Queue}}
        self._subscribers: dict[str, dict[str, asyncio.Queue]] = {}

    def subscribe(self, tenant_id: str, subscriber_id: str) -> asyncio.Queue:
        if tenant_id not in self._subscribers:
            self._subscribers[tenant_id] = {}
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._subscribers[tenant_id][subscriber_id] = queue
        logger.info("sse_subscriber_added", tenant_id=tenant_id, subscriber_id=subscriber_id, total=self.subscriber_count)
        return queue

    def unsubscribe(self, tenant_id: str, subscriber_id: str) -> None:
        if tenant_id in self._subscribers:
            self._subscribers[tenant_id].pop(subscriber_id, None)
            if not self._subscribers[tenant_id]:
                del self._subscribers[tenant_id]
        logger.info("sse_subscriber_removed", tenant_id=tenant_id, subscriber_id=subscriber_id, total=self.subscriber_count)

    async def broadcast(self, event_data: dict, tenant_id: str = "default") -> None:
        """Broadcast event to all subscribers in a specific tenant."""
        if tenant_id not in self._subscribers:
            return
            
        payload = json.dumps(event_data, default=str)
        dead: list[str] = []
        for sid, queue in self._subscribers[tenant_id].items():
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(sid)
                logger.warning("sse_queue_full_dropping", tenant_id=tenant_id, subscriber_id=sid)
        for sid in dead:
            self.unsubscribe(tenant_id, sid)

    async def event_stream(
        self,
        tenant_id: str,
        subscriber_id: str,
        heartbeat_seconds: int = 15,
    ) -> AsyncGenerator[str, None]:
        queue = self.subscribe(tenant_id, subscriber_id)
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
            self.unsubscribe(tenant_id, subscriber_id)

    @property
    def subscriber_count(self) -> int:
        return sum(len(subs) for subs in self._subscribers.values())


# Module-level singleton used by the SOAR engine and other services.
# main.py also creates its own instance for the lifespan scope; if you
# need the lifespan-scoped instance, use dependency injection via
# get_app_broadcaster().  This singleton is a safe fallback for modules
# that import at module-load time (e.g. engine.py).
broadcaster = SSEBroadcaster()
