"""Tests for CanonicalEvent schema validation."""
from app.schemas.canonical_event import (
    CanonicalEvent, Entity, EntityType, NetworkInfo,
    ActionType, OutcomeType, SeverityLevel,
    MLScores, MitreMapping,
)


class TestCanonicalEventCreation:
    def test_minimal_event(self):
        event = CanonicalEvent(source_type="suricata")
        assert event.source_type == "suricata"
        assert event.event_id is not None
        assert event.timestamp is not None

    def test_full_event(self):
        event = CanonicalEvent(
            source_type="suricata",
            action=ActionType.ALERT,
            severity=SeverityLevel.HIGH,
            message="Test alert",
            source_entity=Entity(entity_type=EntityType.IP, identifier="10.0.0.1"),
            network=NetworkInfo(src_ip="10.0.0.1", dst_ip="192.168.1.1", dst_port=443),
        )
        assert event.action == ActionType.ALERT
        assert event.severity == SeverityLevel.HIGH
        assert event.source_entity.identifier == "10.0.0.1"
        assert event.network.dst_port == 443

    def test_default_ml_scores(self):
        event = CanonicalEvent(source_type="test")
        assert event.ml_scores.ensemble_score == 0.0
        assert event.ml_scores.meta_score == 0.0
        assert event.ml_scores.mitre_predictions == []

    def test_ml_scores_assignment(self):
        event = CanonicalEvent(source_type="test")
        event.ml_scores = MLScores(
            ensemble_score=0.85,
            ensemble_label="brute_force",
            meta_score=0.72,
        )
        assert event.ml_scores.ensemble_score == 0.85
        assert event.ml_scores.ensemble_label == "brute_force"


class TestSerialization:
    def test_json_roundtrip(self):
        event = CanonicalEvent(
            source_type="zeek",
            action=ActionType.CONNECT,
            severity=SeverityLevel.MEDIUM,
            message="Connection established",
            source_entity=Entity(entity_type=EntityType.IP, identifier="10.0.1.5"),
        )
        json_data = event.model_dump(mode="json")
        restored = CanonicalEvent(**json_data)
        assert restored.source_type == "zeek"
        assert restored.action == ActionType.CONNECT
        assert restored.source_entity.identifier == "10.0.1.5"

    def test_json_with_ml_scores(self):
        event = CanonicalEvent(
            source_type="test",
            ml_scores=MLScores(
                ensemble_score=0.8,
                meta_score=0.65,
                mitre_predictions=[
                    MitreMapping(
                        technique_id="T1046",
                        technique_name="Network Service Discovery",
                        tactic="discovery",
                        confidence=0.9,
                    )
                ],
            ),
        )
        json_data = event.model_dump(mode="json")
        assert json_data["ml_scores"]["ensemble_score"] == 0.8
        assert len(json_data["ml_scores"]["mitre_predictions"]) == 1


class TestEnumValues:
    def test_entity_types(self):
        for t in ["ip", "user", "host", "domain", "process", "file", "service"]:
            assert EntityType(t) is not None

    def test_action_types(self):
        for a in ["allow", "block", "drop", "alert", "deny", "authenticate", "execute", "connect", "modify", "unknown"]:
            assert ActionType(a) is not None

    def test_severity_levels(self):
        for s in ["info", "low", "medium", "high", "critical"]:
            assert SeverityLevel(s) is not None

    def test_outcome_types(self):
        for o in ["success", "failure", "unknown"]:
            assert OutcomeType(o) is not None


class TestFieldConstraints:
    def test_asset_criticality_range(self):
        entity = Entity(entity_type=EntityType.IP, identifier="10.0.0.1", asset_criticality=0.5)
        assert entity.asset_criticality == 0.5

    def test_ml_score_range(self):
        scores = MLScores(ensemble_score=0.5, meta_score=0.7)
        assert 0.0 <= scores.ensemble_score <= 1.0
        assert 0.0 <= scores.meta_score <= 1.0
