"""Redis store — hot-path entity state and caching.

Stores entity state vectors, active campaign indexes,
connector heartbeats, and SSE subscriber registries.
Sub-millisecond reads on every pipeline event.
"""
from __future__ import annotations

import json
from typing import Optional

import redis.asyncio as aioredis

from app.config import settings

import structlog

logger = structlog.get_logger(__name__)

# ── Lua script: atomic entity state update ────────────────
# Runs inside Redis to avoid read-modify-write race conditions.
# KEYS[1] = entity state key
# ARGV[1] = event_ts (float as string)
# ARGV[2] = dst_ip (empty string if none)
# ARGV[3] = dst_port (empty string if none)
# ARGV[4] = campaign_id (empty string if none)
# ARGV[5] = ttl_seconds
_LUA_UPDATE_ENTITY_STATE = """
local key = KEYS[1]
local event_ts = tonumber(ARGV[1])
local dst_ip = ARGV[2]
local dst_port = ARGV[3]
local campaign_id = ARGV[4]
local ttl = tonumber(ARGV[5])

-- Load existing state or create empty
local raw = redis.call('GET', key)
local state
if raw then
    state = cjson.decode(raw)
else
    state = {
        p_recon = 0, p_cred_stuffing = 0, p_lateral = 0,
        p_exfil = 0, p_persistence = 0, event_count = 0,
        events_5m = 0, events_1h = 0,
        unique_dst_ips_1h = {}, unique_dst_ports_1h = {}
    }
end

-- Timestamps and gap
local last_seen = state.last_seen or event_ts
local gap = event_ts - last_seen
if gap < 0 then gap = 0 end

state.last_seen = event_ts
state.event_count = (state.event_count or 0) + 1

-- Sliding window: 5-minute
if gap > 300 then
    state.events_5m = 1
else
    state.events_5m = (state.events_5m or 0) + 1
end

-- Sliding window: 1-hour
if gap > 3600 then
    state.events_1h = 1
    state.unique_dst_ips_1h = {}
    state.unique_dst_ports_1h = {}
else
    state.events_1h = (state.events_1h or 0) + 1
end

-- Track unique destination IPs (capped at 100)
if dst_ip ~= "" then
    local ips = state.unique_dst_ips_1h or {}
    local found = false
    for _, v in ipairs(ips) do
        if v == dst_ip then found = true; break end
    end
    if not found then
        table.insert(ips, dst_ip)
        if #ips > 100 then table.remove(ips, 1) end
    end
    state.unique_dst_ips_1h = ips
end

-- Track unique destination ports (capped at 100)
if dst_port ~= "" then
    local ports = state.unique_dst_ports_1h or {}
    local found = false
    for _, v in ipairs(ports) do
        if v == dst_port then found = true; break end
    end
    if not found then
        table.insert(ports, dst_port)
        if #ports > 100 then table.remove(ports, 1) end
    end
    state.unique_dst_ports_1h = ports
end

-- Campaign attachment
if campaign_id ~= "" then
    state.campaign_id = campaign_id
end

-- Persist with TTL
local encoded = cjson.encode(state)
redis.call('SETEX', key, ttl, encoded)
return encoded
"""

class RedisStore:
    """Async Redis client for the hot path."""

    def __init__(self) -> None:
        self._pool: Optional[aioredis.Redis] = None
        self._fallback_data: dict[str, any] = {}
        self._lua_update_entity_sha: Optional[str] = None

    async def connect(self) -> None:
        if settings.redis_cluster_mode:
            from redis.asyncio.cluster import RedisCluster
            self._pool = RedisCluster.from_url(
                settings.redis_url,
                decode_responses=True,
            )
        elif settings.redis_sentinel_hosts:
            from redis.asyncio.sentinel import Sentinel
            sentinels = []
            for h in settings.redis_sentinel_hosts:
                parts = h.split(":")
                port = int(parts[1]) if len(parts) > 1 else 26379
                sentinels.append((parts[0], port))
            
            sentinel_client = Sentinel(sentinels, socket_timeout=0.2)
            self._pool = sentinel_client.master_for(
                settings.redis_sentinel_master,
                decode_responses=True,
                max_connections=50,
            )
        else:
            self._pool = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
                max_connections=50,
            )
        await self._pool.ping()
        logger.info("redis_connected", url=settings.redis_url)

        # Pre-load the Lua script for atomic entity state updates
        self._lua_update_entity_sha = await self._pool.script_load(
            _LUA_UPDATE_ENTITY_STATE
        )
        logger.info("redis_lua_entity_update_loaded")

    async def close(self) -> None:
        if self._pool:
            await self._pool.aclose()

    @property
    def client(self) -> aioredis.Redis:
        if not self._pool:
            raise RuntimeError("Redis not initialized. Call connect() first.")
        return self._pool

    # ── Entity State ─────────────────────────────────────

    async def get_entity_state(self, tenant_id: str, entity_id: str) -> Optional[dict]:
        key = f"entity:{tenant_id}:{entity_id}"
        if not self._pool:
            raw = self._fallback_data.get(key)
        else:
            raw = await self.client.get(key)
        return json.loads(raw) if raw else None

    async def set_entity_state(
        self,
        tenant_id: str,
        entity_id: str,
        state: dict,
        ttl_seconds: int = 86400,
    ) -> None:
        key = f"entity:{tenant_id}:{entity_id}"
        if not self._pool:
            self._fallback_data[key] = json.dumps(state)
        else:
            await self.client.setex(key, ttl_seconds, json.dumps(state))

    async def atomic_update_entity_state(
        self,
        tenant_id: str,
        entity_id: str,
        *,
        event_ts: float,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        campaign_id: Optional[str] = None,
        ttl_seconds: int = 86400,
    ) -> dict:
        """Atomically update entity state via Lua script.

        Eliminates the read-modify-write race condition by performing
        all counter increments, sliding window resets, and unique
        destination tracking in a single Redis round-trip.

        Per @cc-skill-backend-patterns (caching layer pattern) and
        @error-handling-patterns (atomic operations).
        """
        key = f"entity:{tenant_id}:{entity_id}"

        if not self._pool:
            # Fallback: use the non-atomic path
            state = await self.get_entity_state(tenant_id, entity_id) or {}
            state["event_count"] = state.get("event_count", 0) + 1
            state["last_seen"] = event_ts
            if campaign_id:
                state["campaign_id"] = campaign_id
            await self.set_entity_state(tenant_id, entity_id, state, ttl_seconds)
            return state

        result = await self.client.evalsha(
            self._lua_update_entity_sha,
            1,  # numkeys
            key,
            str(event_ts),
            dst_ip or "",
            str(dst_port) if dst_port else "",
            campaign_id or "",
            str(ttl_seconds),
        )
        return json.loads(result)

    # ── Campaign Index ───────────────────────────────────

    async def add_entity_to_campaign(
        self, tenant_id: str, campaign_id: str, entity_id: str
    ) -> None:
        key = f"campaign:{tenant_id}:{campaign_id}:entities"
        if not self._pool:
            if key not in self._fallback_data:
                self._fallback_data[key] = set()
            self._fallback_data[key].add(entity_id)
        else:
            await self.client.sadd(key, entity_id)

    async def get_campaign_entities(
        self, tenant_id: str, campaign_id: str
    ) -> set[str]:
        key = f"campaign:{tenant_id}:{campaign_id}:entities"
        if not self._pool:
            return self._fallback_data.get(key, set())
        return await self.client.smembers(key)

    async def get_all_campaigns(self, tenant_id: str) -> list[dict]:
        """Scan and retrieve all active campaigns for a tenant."""
        pattern_prefix = f"campaign_meta:{tenant_id}:"
        campaigns = []
        
        if not self._pool:
            keys = [k for k in self._fallback_data.keys() if k.startswith(pattern_prefix)]
            for key in keys:
                meta_str = self._fallback_data.get(key)
                await self._process_campaign_meta(tenant_id, key, meta_str, campaigns)
        else:
            pattern = f"{pattern_prefix}*"
            async for key in self.client.scan_iter(match=pattern):
                meta_str = await self.client.get(key)
                await self._process_campaign_meta(tenant_id, key, meta_str, campaigns)
        
        # Sort by date descending
        campaigns.sort(key=lambda x: x.get("date", ""), reverse=True)
        return campaigns

    async def _process_campaign_meta(self, tenant_id: str, key: str, meta_str: str | None, campaigns: list[dict]) -> None:
        if not meta_str:
            return
        try:
            # Handle both stringified dicts (from CampaignEngine) and standard JSON
            if meta_str.startswith("{"):
                try:
                    meta = json.loads(meta_str)
                except json.JSONDecodeError:
                    import ast
                    meta = ast.literal_eval(meta_str)
            else:
                import ast
                meta = ast.literal_eval(meta_str)

            parts = key.split(":")
            if len(parts) >= 3:
                campaign_id = parts[2]
                entities = await self.get_campaign_entities(tenant_id, campaign_id)
                # Align with frontend interface:
                # { id, severity, stage, active, affected_assets, meta_score, created_at }
                campaigns.append({
                    "id": campaign_id,
                    "severity": meta.get("severity", "medium"),
                    "stage": meta.get("stage", "initial_access"),
                    "active": meta.get("active", True),
                    "affected_assets": len(entities),
                    "meta_score": meta.get("meta_score", 0.6),
                    "created_at": meta.get("created_at"),
                })
        except Exception as e:
            logger.warning("failed_to_parse_campaign_meta", key=key, error=str(e))

    # ── Connector Heartbeat ──────────────────────────────

    async def record_heartbeat(self, connector_id: str) -> None:
        key = f"heartbeat:{connector_id}"
        await self.client.setex(key, 120, "alive")

    async def is_connector_alive(self, connector_id: str) -> bool:
        key = f"heartbeat:{connector_id}"
        return await self.client.exists(key) > 0

    # ── Generic Cache ────────────────────────────────────

    async def cache_get(self, key: str) -> Optional[str]:
        if not self._pool:
            return self._fallback_data.get(key)
        return await self.client.get(key)

    async def cache_set(self, key: str, value: str, ttl: int = 300) -> None:
        if not self._pool:
            self._fallback_data[key] = value
        else:
            await self.client.setex(key, ttl, value)
