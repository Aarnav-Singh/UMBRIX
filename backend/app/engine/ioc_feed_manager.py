"""IOC Feed Manager — periodic download and caching of external threat feeds.

Downloads indicators from Abuse.ch (Feodo Tracker, URLHaus) and
AlienVault OTX, stores them in Redis with a 24-hour TTL, and provides
a live-lookup fallback for cache misses via the OTX API.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

_REDIS_TTL_SECONDS = 86400  # 24 hours


class IOCFeedManager:
    """Background feed downloader and Redis-backed IOC cache."""

    def __init__(
        self,
        redis_client: Any | None = None,
        otx_api_key: str = "",
        feed_interval_hours: int = 6,
    ) -> None:
        self._redis = redis_client
        self._otx_key = otx_api_key
        self._feed_interval = feed_interval_hours
        self._running = False
        logger.info(
            "ioc_feed_manager_initialized",
            has_redis=redis_client is not None,
            has_otx_key=bool(otx_api_key),
            feed_interval_hours=feed_interval_hours,
        )

    # ── Background loop ──────────────────────────────────

    async def start_background_feeds(self) -> None:
        """Start periodic feed download task (runs until ``stop()`` is called)."""
        self._running = True
        logger.info("ioc_feeds_background_start")
        while self._running:
            await self._download_abuse_ch_feeds()
            await self._download_otx_feeds()
            await asyncio.sleep(self._feed_interval * 3600)

    async def stop(self) -> None:
        """Signal the background loop to exit."""
        self._running = False
        logger.info("ioc_feeds_background_stop")

    # ── Abuse.ch feeds ───────────────────────────────────

    async def _download_abuse_ch_feeds(self) -> None:
        """Download from Abuse.ch Feodo Tracker + URLHaus."""
        try:
            import httpx
        except ImportError:
            logger.warning("httpx_not_installed_skipping_abuse_ch")
            return

        # Feodo Tracker — recommended IP blocklist
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
                )
                resp.raise_for_status()
                data = resp.json()

                count = 0
                for entry in data if isinstance(data, list) else []:
                    ip = entry.get("ip_address") or entry.get("ip")
                    if not ip:
                        continue
                    ioc_data = {
                        "type": "c2",
                        "threat": entry.get("malware", "Feodo Tracker IOC"),
                        "confidence": 0.85,
                        "source": "abuse_ch_feodo",
                    }
                    await self._store_in_redis("ip", ip, ioc_data)
                    count += 1

                logger.info("abuse_ch_feodo_downloaded", ioc_count=count)
        except Exception as exc:
            logger.warning("abuse_ch_feodo_error", error=str(exc))

        # URLHaus — recent malicious URLs
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    "https://urlhaus.abuse.ch/downloads/json_recent/"
                )
                resp.raise_for_status()
                data = resp.json()

                count = 0
                urls = data if isinstance(data, list) else data.get("urls", []) if isinstance(data, dict) else []
                for entry in urls:
                    url = entry.get("url", "")
                    if not url:
                        continue
                    ioc_data = {
                        "type": "malware",
                        "threat": entry.get("threat", "URLHaus Malicious URL"),
                        "confidence": 0.80,
                        "source": "abuse_ch_urlhaus",
                    }
                    await self._store_in_redis("url", url, ioc_data)
                    count += 1

                logger.info("abuse_ch_urlhaus_downloaded", ioc_count=count)
        except Exception as exc:
            logger.warning("abuse_ch_urlhaus_error", error=str(exc))

    # ── AlienVault OTX feeds ─────────────────────────────

    async def _download_otx_feeds(self) -> None:
        """Download from AlienVault OTX subscribed pulses."""
        if not self._otx_key:
            logger.debug("otx_api_key_not_set_skipping")
            return

        try:
            import httpx
        except ImportError:
            logger.warning("httpx_not_installed_skipping_otx")
            return

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    "https://otx.alienvault.com/api/v1/pulses/subscribed",
                    headers={"X-OTX-API-KEY": self._otx_key},
                    params={"limit": 50},
                )
                resp.raise_for_status()
                data = resp.json()

                count = 0
                for pulse in data.get("results", []):
                    pulse_name = pulse.get("name", "OTX Pulse")
                    for indicator in pulse.get("indicators", []):
                        ind_type = indicator.get("type", "")
                        ind_value = indicator.get("indicator", "")
                        if not ind_value:
                            continue

                        # Map OTX indicator types to our types
                        if ind_type in ("IPv4", "IPv6"):
                            cache_type = "ip"
                        elif ind_type in ("domain", "hostname"):
                            cache_type = "domain"
                        elif ind_type in ("URL", "URI"):
                            cache_type = "url"
                        elif ind_type in ("FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"):
                            cache_type = "hash"
                        else:
                            continue

                        ioc_data = {
                            "type": "threat_intel",
                            "threat": pulse_name,
                            "confidence": 0.75,
                            "source": "otx",
                        }
                        await self._store_in_redis(cache_type, ind_value, ioc_data)
                        count += 1

                logger.info("otx_feeds_downloaded", ioc_count=count)
        except Exception as exc:
            logger.warning("otx_download_error", error=str(exc))

    # ── Lookup methods ───────────────────────────────────

    async def lookup_live(self, indicator_type: str, indicator: str) -> dict | None:
        """Live API fallback for cache miss.

        Check Redis first, then call OTX API for IPs if available.
        """
        # Check Redis cache first
        cached = await self.check_redis_cache(indicator_type, indicator)
        if cached:
            return cached

        # Live OTX lookup for IPs only
        if not self._otx_key or indicator_type != "ip":
            return None

        try:
            import httpx
        except ImportError:
            return None

        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general",
                    headers={"X-OTX-API-KEY": self._otx_key},
                )
                resp.raise_for_status()
                data = resp.json()

                pulse_count = data.get("pulse_info", {}).get("count", 0)
                if pulse_count > 0:
                    result = {
                        "type": "threat_intel",
                        "threat": f"OTX: {pulse_count} pulse(s) reference this IP",
                        "confidence": min(0.5 + pulse_count * 0.1, 0.95),
                        "source": "otx_live",
                    }
                    # Cache for future lookups
                    await self._store_in_redis(indicator_type, indicator, result)
                    return result

        except Exception as exc:
            logger.debug("otx_live_lookup_error", indicator=indicator, error=str(exc))

        return None

    async def check_redis_cache(self, indicator_type: str, indicator: str) -> dict | None:
        """Check Redis cache for a previously downloaded IOC."""
        if not self._redis:
            return None

        key = f"ioc:{indicator_type}:{indicator}"
        try:
            raw = await self._redis.get(key)
            if raw:
                return json.loads(raw) if isinstance(raw, (str, bytes)) else raw
        except Exception as exc:
            logger.debug("redis_cache_check_error", key=key, error=str(exc))

        return None

    # ── Internal helpers ─────────────────────────────────

    async def _store_in_redis(self, indicator_type: str, indicator: str, data: dict) -> None:
        """Store an IOC entry in Redis with a 24-hour TTL."""
        if not self._redis:
            return

        key = f"ioc:{indicator_type}:{indicator}"
        try:
            await self._redis.set(key, json.dumps(data), ex=_REDIS_TTL_SECONDS)
        except Exception as exc:
            logger.debug("redis_store_error", key=key, error=str(exc))
