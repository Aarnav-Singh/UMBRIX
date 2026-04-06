"""Entity Resolution — Canonicalization & Deduplication Layer.

Sits between ingestion and the campaign engine to resolve
entity identity across different data sources:
  - IP addresses → hosts (via DHCP/ARP logs)
  - Usernames → canonical identities (via Active Directory/IdP)
  - Hostnames → normalized FQDNs

This is a data-enrichment layer, NOT an ML model.
Placed in engine/ per architectural review.

Phase 22D: Market-required feature for MSSP/MSP multi-tenancy
where the same asset may appear under different identifiers
across different data sources.
"""
from __future__ import annotations

from typing import Optional, Any

import structlog

logger = structlog.get_logger(__name__)


class EntityResolver:
    """Resolves and canonicalizes entity identifiers.

    Maintains a mapping cache (backed by Redis) that associates
    IPs, hostnames, and usernames to canonical entity records.
    """

    def __init__(self, redis: Any = None) -> None:
        self._redis = redis
        self._local_cache: dict[str, str] = {}  # identifier -> canonical_id
        self._ip_to_host: dict[str, str] = {}
        self._user_aliases: dict[str, str] = {}

    # ── Core Resolution ──────────────────────────────────

    async def resolve(
        self,
        identifier: str,
        entity_type: str,
        tenant_id: str = "default",
    ) -> str:
        """Resolve an identifier to its canonical form.

        Args:
            identifier: Raw identifier (IP, hostname, username).
            entity_type: One of "ip", "host", "user", "domain".
            tenant_id: Tenant scope for multi-tenancy.

        Returns:
            Canonical identifier string.
        """
        cache_key = f"{tenant_id}:{entity_type}:{identifier}"

        # Check local cache first
        if cache_key in self._local_cache:
            return self._local_cache[cache_key]

        # Check Redis cache
        if self._redis:
            try:
                cached = await self._redis.cache_get(f"entity_resolve:{cache_key}")
                if cached:
                    self._local_cache[cache_key] = cached
                    return cached
            except Exception:
                pass

        # Apply resolution rules
        canonical = self._apply_rules(identifier, entity_type)

        # Cache the result
        self._local_cache[cache_key] = canonical
        if self._redis:
            try:
                await self._redis.cache_set(
                    f"entity_resolve:{cache_key}",
                    canonical,
                    ttl=3600,  # 1 hour TTL
                )
            except Exception:
                pass

        return canonical

    def _apply_rules(self, identifier: str, entity_type: str) -> str:
        """Apply normalization rules based on entity type."""
        if entity_type == "ip":
            return self._normalize_ip(identifier)
        elif entity_type == "host":
            return self._normalize_hostname(identifier)
        elif entity_type == "user":
            return self._normalize_username(identifier)
        elif entity_type == "domain":
            return self._normalize_domain(identifier)
        return identifier.strip().lower()

    # ── IP Resolution ────────────────────────────────────

    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address format."""
        ip = ip.strip()

        # IPv4-mapped IPv6 → IPv4
        if ip.startswith("::ffff:"):
            ip = ip[7:]

        # Remove leading zeros in octets (010.001.002.003 → 10.1.2.3)
        if "." in ip and ":" not in ip:
            parts = ip.split(".")
            try:
                ip = ".".join(str(int(p)) for p in parts)
            except ValueError:
                pass

        return ip

    def register_dhcp_mapping(self, ip: str, hostname: str, tenant_id: str = "default") -> None:
        """Register an IP-to-hostname mapping from DHCP logs.

        Called during ingestion when DHCP lease events are parsed.
        """
        normalized_ip = self._normalize_ip(ip)
        normalized_host = self._normalize_hostname(hostname)
        self._ip_to_host[f"{tenant_id}:{normalized_ip}"] = normalized_host
        logger.debug("dhcp_mapping_registered", ip=normalized_ip, host=normalized_host)

    def get_host_for_ip(self, ip: str, tenant_id: str = "default") -> Optional[str]:
        """Look up the hostname for an IP address."""
        key = f"{tenant_id}:{self._normalize_ip(ip)}"
        return self._ip_to_host.get(key)

    # ── Hostname Resolution ──────────────────────────────

    def _normalize_hostname(self, hostname: str) -> str:
        """Normalize hostname to lowercase FQDN."""
        hostname = hostname.strip().lower()

        # Remove trailing dot (DNS FQDN notation)
        if hostname.endswith("."):
            hostname = hostname[:-1]

        return hostname

    # ── Username Resolution ──────────────────────────────

    def _normalize_username(self, username: str) -> str:
        """Normalize username format.

        Handles:
          - DOMAIN\\user → user@domain
          - user@DOMAIN.COM → user@domain.com
          - USER → user (lowercase)
        """
        username = username.strip()

        # NTLM format: DOMAIN\user
        if "\\" in username:
            parts = username.split("\\", 1)
            domain = parts[0].lower()
            user = parts[1].lower()
            return f"{user}@{domain}"

        # UPN format: user@domain
        if "@" in username:
            return username.lower()

        # Plain username
        return username.lower()

    def register_user_alias(
        self, alias: str, canonical: str, tenant_id: str = "default"
    ) -> None:
        """Register a username alias from Active Directory/IdP.

        Called when identity provider data maps multiple identifiers
        to the same person (e.g., email, SAM account name, UPN).
        """
        normalized_alias = self._normalize_username(alias)
        normalized_canonical = self._normalize_username(canonical)
        self._user_aliases[f"{tenant_id}:{normalized_alias}"] = normalized_canonical
        logger.debug("user_alias_registered", alias=normalized_alias, canonical=normalized_canonical)

    def get_canonical_user(self, username: str, tenant_id: str = "default") -> str:
        """Resolve a username to its canonical identity."""
        key = f"{tenant_id}:{self._normalize_username(username)}"
        return self._user_aliases.get(key, self._normalize_username(username))

    # ── Domain Resolution ────────────────────────────────

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain names."""
        domain = domain.strip().lower()
        if domain.endswith("."):
            domain = domain[:-1]
        return domain

    # ── Batch Enrichment ─────────────────────────────────

    async def enrich_event(self, event: Any, tenant_id: str = "default") -> Any:
        """Enrich a CanonicalEvent with resolved entity identifiers.

        Resolves source and destination entities to canonical forms
        and adds hostname lookups where available.
        """
        if hasattr(event, "source_entity") and event.source_entity:
            src = event.source_entity
            src.identifier = await self.resolve(
                src.identifier, src.entity_type.value, tenant_id
            )
            # Add hostname from DHCP if source is IP
            if src.entity_type.value == "ip" and not src.hostname:
                host = self.get_host_for_ip(src.identifier, tenant_id)
                if host:
                    src.hostname = host

        if hasattr(event, "destination_entity") and event.destination_entity:
            dst = event.destination_entity
            dst.identifier = await self.resolve(
                dst.identifier, dst.entity_type.value, tenant_id
            )
            if dst.entity_type.value == "ip" and not dst.hostname:
                host = self.get_host_for_ip(dst.identifier, tenant_id)
                if host:
                    dst.hostname = host

        return event

    # ── Cache Stats ──────────────────────────────────────

    @property
    def cache_size(self) -> int:
        return len(self._local_cache)

    @property
    def dhcp_mappings(self) -> int:
        return len(self._ip_to_host)

    @property
    def user_aliases_count(self) -> int:
        return len(self._user_aliases)
