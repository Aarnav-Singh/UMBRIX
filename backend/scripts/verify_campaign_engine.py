"""Standalone verification script for Phase 23A kill-chain stage tracking."""
import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.campaign_engine import CampaignEngine, KILL_CHAIN_ORDER
from app.schemas.canonical_event import CanonicalEvent, MLScores, MitreMapping, Entity, EntityType

class MockRedisStore:
    def __init__(self):
        self._cache = {}
        self._entity_states = {}
        self._campaigns = {}

    async def get_entity_state(self, tenant_id, entity_id):
        return self._entity_states.get(f"{tenant_id}:{entity_id}")

    async def set_entity_state(self, tenant_id, entity_id, state, ttl_seconds=86400):
        self._entity_states[f"{tenant_id}:{entity_id}"] = state

    async def add_entity_to_campaign(self, tenant_id, campaign_id, entity_id):
        key = f"campaign:{tenant_id}:{campaign_id}:entities"
        if key not in self._campaigns:
            self._campaigns[key] = set()
        self._campaigns[key].add(entity_id)
        
        # update state
        state = self._entity_states.get(f"{tenant_id}:{entity_id}", {})
        state["campaign_id"] = campaign_id
        self._entity_states[f"{tenant_id}:{entity_id}"] = state

    async def get_campaign_entities(self, tenant_id, campaign_id):
        key = f"campaign:{tenant_id}:{campaign_id}:entities"
        return self._campaigns.get(key, set())

    async def cache_set(self, key, value, ttl=300):
        self._cache[key] = value

    async def cache_get(self, key):
        return self._cache.get(key)


def build_event(score, tactic):
    event = CanonicalEvent(source_type="suricata")
    event.ml_scores = MLScores(meta_score=score)
    event.source_entity = Entity(entity_type=EntityType.IP, identifier="10.0.0.5")
    if tactic:
        event.ml_scores.mitre_predictions = [MitreMapping(technique_id="T1", technique_name="T1", tactic=tactic, confidence=0.9)]
    return event


def build_event_dst(score, tactic, src="10.0.0.5", dst="10.0.0.6"):
    event = CanonicalEvent(source_type="suricata")
    event.ml_scores = MLScores(meta_score=score)
    event.source_entity = Entity(entity_type=EntityType.IP, identifier=src)
    event.destination_entity = Entity(entity_type=EntityType.IP, identifier=dst)
    if tactic:
        event.ml_scores.mitre_predictions = [MitreMapping(technique_id="T2", technique_name="T2", tactic=tactic, confidence=0.8)]
    return event

async def main():
    mock_redis = MockRedisStore()
    engine = CampaignEngine(mock_redis)
    
    passed = 0
    failed = 0

    print("Phase 23A Verification: Campaign Engine")
    print("-" * 50)
    
    # 1. Seed a new campaign with Initial Access
    evt1 = build_event(0.7, "initial access")
    cid = await engine.correlate(evt1)
    
    if cid:
        print("[PASS] 1. New Campaign Seeded")
        passed += 1
    else:
        print("[FAIL] 1. New Campaign Failed")
        failed += 1
        
    meta1_str = await mock_redis.cache_get(f"campaign_meta:default:{cid}")
    meta1 = json.loads(meta1_str)
    
    if meta1["stage"] == "initial_access":
        print("[PASS] 2. Campaign started at initial_access")
        passed += 1
    else:
        print(f"[FAIL] 2. Stage is {meta1['stage']} instead of initial_access")
        failed += 1

    # 2. Add a lateral movement event
    evt2 = build_event_dst(0.8, "lateral-movement", "10.0.0.5", "10.0.0.6")
    cid2 = await engine.correlate(evt2)
    
    if cid2 == cid:
        print("[PASS] 3. Event joined existing campaign via dst_ip")
        passed += 1
    else:
        print(f"[FAIL] 3. Event joined {cid2} instead of {cid}")
        failed += 1

    meta2_str = await mock_redis.cache_get(f"campaign_meta:default:{cid}")
    meta2 = json.loads(meta2_str)
    
    if meta2["stage"] == "lateral_movement":
        print(f"[PASS] 4. Stage progressed correctly to {meta2['stage']}")
        passed += 1
    else:
        print(f"[FAIL] 4. Expected lateral_movement, got {meta2['stage']}")
        failed += 1
        
    # 3. Add an execution event (earlier tactic, should not regress stage)
    evt3 = build_event_dst(0.6, "Execution", "10.0.0.5", "10.0.0.7")
    cid3 = await engine.correlate(evt3)
    
    meta3_str = await mock_redis.cache_get(f"campaign_meta:default:{cid}")
    meta3 = json.loads(meta3_str)
    
    if meta3["stage"] == "lateral_movement":
        print("[PASS] 5. Stage did not regress back to execution")
        passed += 1
    else:
        print(f"[FAIL] 5. Stage regressed to {meta3['stage']}")
        failed += 1

    # 4. Impact event upgrades severity
    evt4 = build_event_dst(0.95, "impact", "10.0.0.5", "10.0.0.8")
    cid4 = await engine.correlate(evt4)
    
    meta4_str = await mock_redis.cache_get(f"campaign_meta:default:{cid}")
    meta4 = json.loads(meta4_str)
    
    if meta4["stage"] == "impact" and meta4["severity"] == "critical":
        print("[PASS] 6. Stage progressed to impact and severity escalated to critical")
        passed += 1
    # 5. Seed a second distinct campaign
    evt5 = build_event(0.8, "initial_access")
    evt5.source_entity.identifier = "10.0.0.9"
    cid5 = await engine.correlate(evt5)
    
    if cid5 and cid5 != cid:
        print("[PASS] 7. Second distinct campaign seeded")
        passed += 1
    else:
        print(f"[FAIL] 7. Expected new campaign, got {cid5}")
        failed += 1

    # 6. Lateral movement bridging the two campaigns (merger)
    evt6 = build_event_dst(0.85, "credential_access", "10.0.0.8", "10.0.0.9")
    cid6 = await engine.correlate(evt6)
    
    if cid6 == cid or cid6 == cid5:
        print(f"[PASS] 8. Campaigns merged successfully into {cid6}")
        passed += 1
    else:
        print(f"[FAIL] 8. Expected merge into '{cid}' or '{cid5}', got '{cid6}'")
        failed += 1
        
    # Check meta of merged campaign
    merged_meta_str = await mock_redis.cache_get(f"campaign_meta:default:{cid6}")
    merged_meta = json.loads(merged_meta_str)
    
    if merged_meta["stage"] == "impact" and merged_meta["severity"] == "critical":
        print("[PASS] 9. Merged campaign retains impact/critical from existing")
        passed += 1
    else:
        print(f"[FAIL] 9. Stage {merged_meta.get('stage')}, Severity {merged_meta.get('severity')}")
        failed += 1
        
    # Check old campaign is inactive
    old_cid = cid if cid6 == cid5 else cid5
    old_meta_str = await mock_redis.cache_get(f"campaign_meta:default:{old_cid}")
    if old_meta_str:
        old_meta = json.loads(old_meta_str)
        if not old_meta.get("active", True) and "merged_into" in old_meta:
            print("[PASS] 10. Old campaign marked inactive and merged")
            passed += 1
        else:
            print(f"[FAIL] 10. Old campaign active={old_meta.get('active')} merged_into={old_meta.get('merged_into')}")
            failed += 1
    else:
        print("[FAIL] 10. Old campaign metadata missing")
        failed += 1
        
    print(f"\nResults: {passed} passed, {failed} failed")
    
    return failed == 0

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
