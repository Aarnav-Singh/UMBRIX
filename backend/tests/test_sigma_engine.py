"""Tests for Sigma rule engine."""
from app.engine.sigma_engine import SigmaEngine
from app.schemas.canonical_event import (
    CanonicalEvent, NetworkInfo,
    ActionType, SeverityLevel, OutcomeType,
)


class TestSigmaEngine:
    def setup_method(self):
        self.engine = SigmaEngine()

    def test_match_cobalt_strike(self):
        event = CanonicalEvent(
            source_type="suricata",
            message="ET MALWARE CobaltStrike Beacon Activity detected",
            severity=SeverityLevel.CRITICAL,
        )
        matches = self.engine.match(event)
        assert len(matches) > 0
        rule_ids = [m["rule_id"] for m in matches]
        assert "sigma-001" in rule_ids

    def test_match_port_scan(self):
        event = CanonicalEvent(
            source_type="zeek",
            message="Nmap port scan detected from external network",
            severity=SeverityLevel.MEDIUM,
        )
        matches = self.engine.match(event)
        rule_ids = [m["rule_id"] for m in matches]
        assert "sigma-003" in rule_ids

    def test_match_sql_injection(self):
        event = CanonicalEvent(
            source_type="waf",
            message="SQL injection attempt: UNION SELECT * FROM users",
            severity=SeverityLevel.HIGH,
        )
        matches = self.engine.match(event)
        rule_ids = [m["rule_id"] for m in matches]
        assert "sigma-004" in rule_ids

    def test_match_smb_lateral_movement(self):
        event = CanonicalEvent(
            source_type="windows",
            action=ActionType.CONNECT,
            network=NetworkInfo(dst_port=445),
        )
        matches = self.engine.match(event)
        rule_ids = [m["rule_id"] for m in matches]
        assert "sigma-005" in rule_ids

    def test_no_false_positives_on_benign(self):
        event = CanonicalEvent(
            source_type="syslog",
            message="System health check completed successfully",
            severity=SeverityLevel.INFO,
            action=ActionType.ALLOW,
        )
        matches = self.engine.match(event)
        # Benign events should match few or no rules
        assert len(matches) <= 1

    def test_mitre_mapping_conversion(self):
        event = CanonicalEvent(
            source_type="suricata",
            message="CobaltStrike beacon detected",
        )
        matches = self.engine.match(event)
        mitre = self.engine.to_mitre_mappings(matches)
        assert len(mitre) > 0
        assert mitre[0].technique_id.startswith("T")
        assert mitre[0].tactic is not None

    def test_brute_force_detection(self):
        event = CanonicalEvent(
            source_type="okta",
            action=ActionType.AUTHENTICATE,
            outcome=OutcomeType.FAILURE,
        )
        matches = self.engine.match(event)
        rule_ids = [m["rule_id"] for m in matches]
        assert "sigma-002" in rule_ids
