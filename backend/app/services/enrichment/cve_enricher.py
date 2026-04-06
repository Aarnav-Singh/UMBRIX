"""CVE/NVD Enrichment Layer — Phase 34B.

Enriches security events with CVE context from NIST NVD API v2.
Uses Redis caching (24h TTL) and respects NVD rate limits.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Regex to extract CVE identifiers from text
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

# NVD API v2 endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limits: 5 req/30s (unauthenticated), 50 req/30s (with key)
RATE_LIMIT_WINDOW = 30  # seconds
RATE_LIMIT_UNAUTH = 5
RATE_LIMIT_AUTH = 50

CACHE_TTL = 86400  # 24 hours


@dataclass
class CveContext:
    """Structured CVE data attached to events."""
    cve_id: str
    cvss_score: float | None = None
    cvss_severity: str | None = None
    affected_products: list[str] | None = None
    patch_available: bool | None = None
    published_date: str | None = None
    description: str | None = None


class CveEnricher:
    """Enriches events with CVE context from NVD API v2.

    Checks Redis cache first, then queries NVD. Respects rate limits
    using a Redis-backed counter.
    """

    def __init__(self, redis_store: Any) -> None:
        self._redis = redis_store
        self._http = httpx.AsyncClient(timeout=10.0)

    async def enrich(self, event: Any) -> Any:
        """Extract CVE references and attach NVD context to the event.

        Checks:
          1. event.sigma_matches[].cve_ids (if present)
          2. event.message field (regex extraction)

        Attaches results to event.enrichment.cve_context.
        """
        cve_ids: set[str] = set()

        # Extract from sigma matches
        sigma_matches = getattr(event, "sigma_matches", None)
        if sigma_matches:
            for match in sigma_matches:
                match_cves = getattr(match, "cve_ids", None) or match.get("cve_ids", []) if isinstance(match, dict) else []
                for cve in match_cves:
                    if CVE_PATTERN.match(cve):
                        cve_ids.add(cve)

        # Extract from event message
        message = getattr(event, "message", "") or ""
        if isinstance(message, str):
            cve_ids.update(CVE_PATTERN.findall(message))

        # Also check raw_log
        raw_log = getattr(event, "raw_log", "") or ""
        if isinstance(raw_log, str):
            cve_ids.update(CVE_PATTERN.findall(raw_log))

        if not cve_ids:
            return event

        # Enrich each CVE
        cve_contexts = []
        for cve_id in sorted(cve_ids)[:10]:  # Cap at 10 CVEs per event
            ctx = await self._lookup_cve(cve_id)
            if ctx:
                cve_contexts.append(ctx)

        # Attach to event
        if cve_contexts:
            if not hasattr(event, "enrichment") or event.enrichment is None:
                try:
                    event.enrichment = {}
                except (AttributeError, TypeError):
                    pass
            try:
                if isinstance(event.enrichment, dict):
                    event.enrichment["cve_context"] = [
                        {
                            "cve_id": c.cve_id,
                            "cvss_score": c.cvss_score,
                            "cvss_severity": c.cvss_severity,
                            "affected_products": c.affected_products,
                            "patch_available": c.patch_available,
                            "published_date": c.published_date,
                            "description": c.description,
                        }
                        for c in cve_contexts
                    ]
            except (AttributeError, TypeError) as exc:
                logger.debug("cve_enrichment_attach_failed", error=str(exc))

        return event

    async def _lookup_cve(self, cve_id: str) -> CveContext | None:
        """Look up a single CVE — cache first, then NVD API."""
        cache_key = f"cve:{cve_id}"

        # Check Redis cache
        cached = await self._redis.cache_get(cache_key)
        if cached:
            try:
                data = json.loads(cached)
                return CveContext(**data)
            except (json.JSONDecodeError, TypeError):
                pass

        # Check rate limit
        if not await self._check_rate_limit():
            logger.debug("nvd_rate_limited", cve_id=cve_id)
            return None

        # Query NVD API
        try:
            headers = {}
            if settings.nvd_api_key:
                headers["apiKey"] = settings.nvd_api_key

            resp = await self._http.get(
                NVD_API_URL,
                params={"cveId": cve_id},
                headers=headers,
            )

            if resp.status_code == 200:
                ctx = self._parse_nvd_response(cve_id, resp.json())
                if ctx:
                    # Cache the result
                    cache_data = json.dumps({
                        "cve_id": ctx.cve_id,
                        "cvss_score": ctx.cvss_score,
                        "cvss_severity": ctx.cvss_severity,
                        "affected_products": ctx.affected_products,
                        "patch_available": ctx.patch_available,
                        "published_date": ctx.published_date,
                        "description": ctx.description,
                    })
                    await self._redis.cache_set(cache_key, cache_data, ttl=CACHE_TTL)
                    return ctx
            elif resp.status_code == 403:
                logger.warning("nvd_api_rate_limited", status=resp.status_code)
            else:
                logger.warning("nvd_api_error", status=resp.status_code, cve_id=cve_id)
        except httpx.HTTPError as exc:
            logger.warning("nvd_api_request_failed", error=str(exc))
        except Exception as exc:
            logger.error("nvd_enrichment_error", error=str(exc))

        return None

    async def _check_rate_limit(self) -> bool:
        """Redis-backed rate limiting for NVD API calls."""
        rate_key = "nvd:rate_counter"
        try:
            count_raw = await self._redis.cache_get(rate_key)
            count = int(count_raw) if count_raw else 0
            limit = RATE_LIMIT_AUTH if settings.nvd_api_key else RATE_LIMIT_UNAUTH

            if count >= limit:
                return False

            # Increment counter
            await self._redis.cache_set(
                rate_key,
                str(count + 1),
                ttl=RATE_LIMIT_WINDOW,
            )
            return True
        except Exception:
            # On Redis failure, allow the request but log
            return True

    def _parse_nvd_response(self, cve_id: str, data: dict) -> CveContext | None:
        """Extract structured CVE data from NVD API v2 response."""
        try:
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            cve_data = vulnerabilities[0].get("cve", {})

            # CVSS scores — try v3.1 first, then v3.0, then v2
            cvss_score = None
            cvss_severity = None
            metrics = cve_data.get("metrics", {})

            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                version_metrics = metrics.get(version_key, [])
                if version_metrics:
                    primary = version_metrics[0]
                    cvss_data = primary.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_severity = cvss_data.get("baseSeverity")
                    break

            # Description
            descriptions = cve_data.get("descriptions", [])
            desc = None
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:500]  # Cap length
                    break

            # Affected products (CPE matches)
            affected = []
            configurations = cve_data.get("configurations", [])
            for config in configurations[:3]:  # Limit to avoid huge lists
                nodes = config.get("nodes", [])
                for node in nodes[:5]:
                    cpe_matches = node.get("cpeMatch", [])
                    for cpe in cpe_matches[:5]:
                        criteria = cpe.get("criteria", "")
                        if criteria:
                            # Extract product name from CPE string
                            parts = criteria.split(":")
                            if len(parts) >= 5:
                                vendor = parts[3]
                                product = parts[4]
                                affected.append(f"{vendor}/{product}")

            # Published date
            published = cve_data.get("published", "")

            return CveContext(
                cve_id=cve_id,
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                affected_products=affected[:10] if affected else None,
                patch_available=None,  # NVD doesn't explicitly track this
                published_date=published[:10] if published else None,
                description=desc,
            )
        except (KeyError, IndexError, TypeError) as exc:
            logger.warning("nvd_parse_error", cve_id=cve_id, error=str(exc))
            return None
