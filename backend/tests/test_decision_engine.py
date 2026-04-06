"""Tests for Decision Engine."""
from app.engine.decision_engine import DecisionEngine
from app.schemas.canonical_event import CanonicalEvent, MLScores


class TestDecisionEngine:
    def setup_method(self):
        self.engine = DecisionEngine()

    def _make_event(self, meta_score: float) -> CanonicalEvent:
        return CanonicalEvent(
            source_type="test",
            ml_scores=MLScores(meta_score=meta_score),
        )

    def test_isolate_threshold(self):
        event = self._make_event(0.9)
        rec = self.engine.recommend(event)
        assert rec["action"] == "ISOLATE"
        assert rec["urgency"] == "immediate"

    def test_block_threshold(self):
        event = self._make_event(0.75)
        rec = self.engine.recommend(event)
        assert rec["action"] == "BLOCK"

    def test_investigate_threshold(self):
        event = self._make_event(0.55)
        rec = self.engine.recommend(event)
        assert rec["action"] == "INVESTIGATE"

    def test_monitor_threshold(self):
        event = self._make_event(0.35)
        rec = self.engine.recommend(event)
        assert rec["action"] == "MONITOR"

    def test_log_threshold(self):
        event = self._make_event(0.1)
        rec = self.engine.recommend(event)
        assert rec["action"] == "LOG"

    def test_ioc_escalation(self):
        event = self._make_event(0.4)
        ioc_matches = [{"confidence": 0.95, "threat_name": "CobaltStrike C2"}]
        rec = self.engine.recommend(event, ioc_matches=ioc_matches)
        # Should escalate from MONITOR to at least BLOCK
        assert rec["action"] in ("BLOCK", "ISOLATE")

    def test_sigma_escalation(self):
        event = self._make_event(0.4)
        sigma_matches = [
            {"confidence": 0.9, "rule_name": "CobaltStrike"},
            {"confidence": 0.85, "rule_name": "C2 Activity"},
        ]
        rec = self.engine.recommend(event, sigma_matches=sigma_matches)
        assert rec["action"] in ("BLOCK", "ISOLATE")

    def test_campaign_escalation(self):
        event = self._make_event(0.25)
        event.campaign_id = "campaign-123"
        rec = self.engine.recommend(event)
        assert rec["action"] in ("INVESTIGATE", "BLOCK", "ISOLATE")

    def test_reasoning_includes_score(self):
        event = self._make_event(0.6)
        rec = self.engine.recommend(event)
        assert "ML composite score" in rec["reasoning"]

    def test_recommendation_has_all_fields(self):
        event = self._make_event(0.5)
        rec = self.engine.recommend(event)
        assert "action" in rec
        assert "urgency" in rec
        assert "description" in rec
        assert "reasoning" in rec
        assert "confidence" in rec
        assert "auto_applicable" in rec
