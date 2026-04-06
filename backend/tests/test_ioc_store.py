"""Tests for IOC store lookups."""
from app.engine.ioc_store import IOCStore
from app.schemas.canonical_event import CanonicalEvent, NetworkInfo


class TestIOCStore:
    def setup_method(self):
        self.store = IOCStore()

    def test_known_bad_ip_match(self):
        event = CanonicalEvent(
            source_type="firewall",
            network=NetworkInfo(dst_ip="198.51.100.22"),
        )
        matches = self.store.lookup(event)
        assert len(matches) > 0
        assert matches[0]["indicator"] == "198.51.100.22"
        assert matches[0]["threat_type"] == "c2"

    def test_clean_ip_no_match(self):
        event = CanonicalEvent(
            source_type="firewall",
            network=NetworkInfo(dst_ip="8.8.8.8"),
        )
        matches = self.store.lookup(event)
        assert len(matches) == 0

    def test_domain_in_message(self):
        event = CanonicalEvent(
            source_type="dns",
            message="DNS query to evil-c2.example.com from internal host",
        )
        matches = self.store.lookup(event)
        assert len(matches) > 0
        assert matches[0]["indicator_type"] == "domain"

    def test_direct_ip_lookup(self):
        result = self.store.lookup_ip("203.0.113.50")
        assert result is not None
        assert result["type"] == "c2"

    def test_direct_ip_miss(self):
        result = self.store.lookup_ip("1.1.1.1")
        assert result is None

    def test_direct_domain_lookup(self):
        result = self.store.lookup_domain("phish-bank.example.com")
        assert result is not None
        assert result["type"] == "phishing"

    def test_hash_lookup(self):
        result = self.store.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result is not None
        assert result["type"] == "malware"

    def test_src_ip_match(self):
        event = CanonicalEvent(
            source_type="firewall",
            network=NetworkInfo(src_ip="192.0.2.200", dst_ip="10.0.0.1"),
        )
        matches = self.store.lookup(event)
        assert len(matches) > 0
        assert matches[0]["indicator"] == "192.0.2.200"
