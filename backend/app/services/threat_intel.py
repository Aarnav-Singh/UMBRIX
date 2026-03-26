"""External Threat Intelligence Integrations (MISP / TAXII / VT / AbuseIPDB)."""
import asyncio
import re
import structlog
import httpx
from datetime import datetime
from app.config import settings
from app.dependencies import get_app_redis, get_app_postgres

logger = structlog.get_logger(__name__)


class ThreatIntelFetcher:
    """Asynchronously fetches IOCs from external feeds."""

    def __init__(self, redis_client, pg_client):
        self.redis = redis_client
        self.pg = pg_client
        self.http_client = httpx.AsyncClient(timeout=15.0)

    # ── MISP ─────────────────────────────────────────────
    async def fetch_misp_feed(self, url: str, api_key: str) -> int:
        """Fetch latest indicators from a MISP instance."""
        if not url or not api_key:
            logger.debug("misp_not_configured_skipping")
            return 0

        headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        payload = {
            "returnFormat": "json",
            "type": ["ip-dst", "ip-src", "domain", "md5", "sha256"],
            "last": "1d",
            "enforceWarninglist": True,
        }

        try:
            response = await self.http_client.post(
                f"{url}/attributes/restSearch", headers=headers, json=payload
            )
            response.raise_for_status()
            data = response.json()

            attributes = data.get("response", {}).get("Attribute", [])
            logger.info("misp_feed_fetched", count=len(attributes), source=url)

            for attr in attributes:
                ioc_value = attr.get("value")
                ioc_type = attr.get("type")
                cache_type = {"ip-dst": "ip", "ip-src": "ip", "domain": "domain", 
                              "md5": "hash", "sha256": "hash"}.get(ioc_type, "other")
                
                if cache_type == "other":
                    continue

                ioc_data = {
                    "type": "threat_intel",
                    "threat": "MISP Attribute",
                    "confidence": 0.85,
                    "source": "misp",
                }
                cache_key = f"ioc:{cache_type}:{ioc_value}"
                import json
                await self.redis.cache_set(
                    cache_key,
                    json.dumps(ioc_data),
                    ttl=86400 * 7,
                )

            return len(attributes)
        except httpx.HTTPError as exc:
            logger.error("misp_fetch_failed", error=str(exc), url=url)
            return 0

    # ── TAXII 2.1 ────────────────────────────────────────
    async def fetch_taxii_collection(self, url: str, collection_id: str, token: str) -> int:
        """Fetch STIX bundles from a TAXII 2.1 Server."""
        if not url or not collection_id:
            logger.debug("taxii_not_configured_skipping")
            return 0

        headers = {
            "Accept": "application/taxii+json;version=2.1",
            "Authorization": f"Bearer {token}",
        }

        try:
            response = await self.http_client.get(
                f"{url}/collections/{collection_id}/objects", headers=headers
            )
            response.raise_for_status()
            data = response.json()

            objects = data.get("objects", [])
            indicators = [obj for obj in objects if obj.get("type") == "indicator"]
            logger.info("taxii_feed_fetched", count=len(indicators), source=url)

            for ind in indicators:
                pattern = ind.get("pattern", "")
                # Parse STIX patterns like [ipv4-addr:value = '1.2.3.4']
                match = re.search(r"(\S+):value\s*=\s*'(.+?)'", pattern)
                if match:
                    stix_type, value = match.groups()
                    cache_type = {"ipv4-addr": "ip", "domain-name": "domain",
                                  "file": "hash", "url": "url"}.get(stix_type, "other")
                else:
                    value = ind.get("id", "")
                    cache_type = "other"
                    
                if cache_type == "other":
                    continue

                ioc_data = {
                    "type": "threat_intel",
                    "threat": f"TAXII Collection: {collection_id}",
                    "confidence": 0.8,
                    "source": "taxii",
                }
                cache_key = f"ioc:{cache_type}:{value}"
                import json
                await self.redis.cache_set(cache_key, json.dumps(ioc_data), ttl=86400 * 7)

            return len(indicators)
        except httpx.HTTPError as exc:
            logger.error("taxii_fetch_failed", error=str(exc), url=url)
            return 0

    # ── VirusTotal ───────────────────────────────────────
    async def lookup_virustotal(self, indicator: str, indicator_type: str = "ip") -> dict | None:
        """Query VirusTotal v3 API for IP, domain, or file hash reputation."""
        if not settings.virustotal_api_key:
            return None

        type_map = {
            "ip": f"ip_addresses/{indicator}",
            "domain": f"domains/{indicator}",
            "hash": f"files/{indicator}",
            "url": f"urls/{indicator}",
        }
        path = type_map.get(indicator_type)
        if not path:
            return None

        try:
            resp = await self.http_client.get(
                f"https://www.virustotal.com/api/v3/{path}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
                result = {
                    "source": "virustotal",
                    "malicious_detections": malicious,
                    "confidence": min(0.3 + malicious * 0.05, 0.99),
                    "reputation": data.get("reputation", 0),
                }
                logger.info("virustotal_lookup", indicator=indicator, malicious=malicious)
                return result
        except Exception as exc:
            logger.warning("virustotal_error", indicator=indicator, error=str(exc))
        return None

    # ── AbuseIPDB ────────────────────────────────────────
    async def lookup_abuseipdb(self, ip: str) -> dict | None:
        """Check an IP address against AbuseIPDB."""
        if not settings.abuseipdb_api_key:
            return None

        try:
            resp = await self.http_client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": ip, "maxAgeInDays": "90"},
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                result = {
                    "source": "abuseipdb",
                    "abuse_score": abuse_score,
                    "total_reports": data.get("totalReports", 0),
                    "confidence": abuse_score / 100.0,
                    "isp": data.get("isp", ""),
                    "country": data.get("countryCode", ""),
                }
                logger.info("abuseipdb_lookup", ip=ip, score=abuse_score)
                return result
        except Exception as exc:
            logger.warning("abuseipdb_error", ip=ip, error=str(exc))
        return None

    # ── Run all feeds ────────────────────────────────────
    async def run_all_feeds(self):
        """Execute all configured feeds concurrently."""
        logger.info("intel_sync_started")
        await asyncio.gather(
            self.fetch_misp_feed(settings.misp_url, settings.misp_api_key),
            self.fetch_taxii_collection(
                settings.taxii_url, settings.taxii_collection_id, settings.taxii_token
            ),
            return_exceptions=True,
        )
        logger.info("intel_sync_completed")


async def scheduled_intel_sync():
    """APScheduler Job to invoke the ThreatIntelFetcher."""
    redis = get_app_redis()
    pg = get_app_postgres()

    fetcher = ThreatIntelFetcher(redis, pg)
    await fetcher.run_all_feeds()
