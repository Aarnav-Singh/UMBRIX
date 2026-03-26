"""Campaign Correlation Engine — attack campaign formation.

Clusters related anomalous events into campaigns using
entity graph adjacency, temporal proximity, and MITRE ATT&CK
kill chain stage progression.
"""
from __future__ import annotations

import json
import uuid
from typing import Optional

from app.schemas.canonical_event import CanonicalEvent
from app.repositories.redis_store import RedisStore

import structlog

logger = structlog.get_logger(__name__)

# MITRE ATT&CK Tactics in progression order
KILL_CHAIN_ORDER = [
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact"
]

class CampaignEngine:
    """Stateful campaign correlation coordinator."""

    def __init__(self, redis: RedisStore) -> None:
        self._redis = redis

    async def correlate(self, event: CanonicalEvent) -> Optional[str]:
        """Determine if this event belongs to an existing campaign
        or should seed a new one.

        Returns campaign_id if event was assigned to a campaign.
        """
        if event.ml_scores.meta_score < 0.3:
            return None  # Below campaign threshold

        tenant_id = event.metadata.tenant_id
        entity_id = self._get_primary_entity(event)
        if not entity_id:
            return None

        # Check if entities already belong to active campaigns
        existing_campaign = await self._find_entity_campaign(tenant_id, entity_id)
        dst_id = self._get_dst_entity(event)
        dst_campaign = await self._find_entity_campaign(tenant_id, dst_id) if dst_id else None

        # Phase 23B: Merge campaigns if both entities are in different campaigns
        if existing_campaign and dst_campaign and existing_campaign != dst_campaign:
            merged_campaign = await self._merge_campaigns(tenant_id, existing_campaign, dst_campaign)
            await self._update_campaign_metadata(tenant_id, merged_campaign, event)
            if dst_id:
                await self._redis.add_entity_to_campaign(tenant_id, merged_campaign, dst_id)
                await self._set_entity_campaign(tenant_id, dst_id, merged_campaign)
            logger.info(
                "campaigns_merged_via_event",
                merged_into=merged_campaign,
                merged_from=dst_campaign,
                entity_id=entity_id,
                dst_id=dst_id
            )
            return merged_campaign

        if existing_campaign:
            await self._redis.add_entity_to_campaign(tenant_id, existing_campaign, entity_id)
            if dst_id:
                await self._redis.add_entity_to_campaign(tenant_id, existing_campaign, dst_id)
                await self._set_entity_campaign(tenant_id, dst_id, existing_campaign)
            await self._update_campaign_metadata(tenant_id, existing_campaign, event)
            logger.info(
                "event_joined_campaign",
                campaign_id=existing_campaign,
                entity_id=entity_id,
            )
            return existing_campaign

        if dst_campaign:
            # Lateral movement to an entity already in a campaign
            await self._redis.add_entity_to_campaign(tenant_id, dst_campaign, entity_id)
            await self._set_entity_campaign(tenant_id, entity_id, dst_campaign)
            await self._update_campaign_metadata(tenant_id, dst_campaign, event)
            logger.info(
                "lateral_movement_detected",
                campaign_id=dst_campaign,
                src=entity_id,
                dst=dst_id,
            )
            return dst_campaign

        # Score is high enough: seed a new campaign
        logger.debug("evaluating_new_campaign", score=event.ml_scores.meta_score, threshold=0.6)
        if event.ml_scores.meta_score >= 0.6:
            campaign_id = f"campaign-{uuid.uuid4().hex[:12]}"
            
            # Phase 23A: Extract initial tactic
            tactic = self._extract_highest_confidence_tactic(event) or "initial_access"
            
            logger.info("seeding_new_campaign", campaign_id=campaign_id, score=event.ml_scores.meta_score, stage=tactic)
            await self._redis.add_entity_to_campaign(tenant_id, campaign_id, entity_id)
            if dst_id:
                await self._redis.add_entity_to_campaign(tenant_id, campaign_id, dst_id)
                await self._set_entity_campaign(tenant_id, dst_id, campaign_id)
                
            # Store campaign metadata
            await self._redis.cache_set(
                f"campaign_meta:{tenant_id}:{campaign_id}",
                json.dumps({
                    "created_at": event.timestamp.isoformat(),
                    "seed_event": event.event_id,
                    "severity": event.severity.value,
                    "stage": tactic,
                    "meta_score": event.ml_scores.meta_score,
                    "active": True,
                }),
                ttl=86400 * 7,  # 7 days
            )
            logger.info(
                "new_campaign_seeded",
                campaign_id=campaign_id,
                entity_id=entity_id,
                meta_score=event.ml_scores.meta_score,
                stage=tactic
            )
            return campaign_id
        
        logger.debug("no_campaign_formed", score=event.ml_scores.meta_score)
        return None

    async def _set_entity_campaign(self, tenant_id: str, entity_id: str, campaign_id: str) -> None:
        """Update the campaign_id pointer in the entity's hot state."""
        state = await self._redis.get_entity_state(tenant_id, entity_id)
        if state and state.get("campaign_id") != campaign_id:
            state["campaign_id"] = campaign_id
            await self._redis.set_entity_state(tenant_id, entity_id, state)

    async def _merge_campaigns(self, tenant_id: str, target_campaign: str, source_campaign: str) -> str:
        """Merge source_campaign into target_campaign."""
        # 1. Get all entities from source
        src_entities = await self._redis.get_campaign_entities(tenant_id, source_campaign)
        
        # 2. Add them to target and update their state pointer
        for ent in src_entities:
            await self._redis.add_entity_to_campaign(tenant_id, target_campaign, ent)
            await self._set_entity_campaign(tenant_id, ent, target_campaign)
            
        # 3. Merge metadata
        src_meta_str = await self._redis.cache_get(f"campaign_meta:{tenant_id}:{source_campaign}")
        tgt_meta_str = await self._redis.cache_get(f"campaign_meta:{tenant_id}:{target_campaign}")
        
        try:
            tgt_meta = json.loads(tgt_meta_str) if tgt_meta_str and tgt_meta_str.startswith("{") else {"active": True, "meta_score": 0, "stage": "initial_access"}
            src_meta = json.loads(src_meta_str) if src_meta_str and src_meta_str.startswith("{") else {}
            
            # Update target with max score from source
            if src_meta.get("meta_score", 0) > tgt_meta.get("meta_score", 0):
                tgt_meta["meta_score"] = src_meta["meta_score"]
                if tgt_meta["meta_score"] >= 0.9:
                    tgt_meta["severity"] = "critical"
                elif tgt_meta["meta_score"] >= 0.75:
                    tgt_meta["severity"] = "high"
                    
            # Compare stages and take the further one
            src_stage = src_meta.get("stage", "initial_access")
            tgt_stage = tgt_meta.get("stage", "initial_access")
            src_idx = KILL_CHAIN_ORDER.index(src_stage) if src_stage in KILL_CHAIN_ORDER else -1
            tgt_idx = KILL_CHAIN_ORDER.index(tgt_stage) if tgt_stage in KILL_CHAIN_ORDER else -1
            if src_idx > tgt_idx:
                tgt_meta["stage"] = src_stage
                
            await self._redis.cache_set(f"campaign_meta:{tenant_id}:{target_campaign}", json.dumps(tgt_meta), ttl=86400 * 7)
            
            # Mark source as inactive and merged
            if src_meta:
                src_meta["active"] = False
                src_meta["merged_into"] = target_campaign
                await self._redis.cache_set(f"campaign_meta:{tenant_id}:{source_campaign}", json.dumps(src_meta), ttl=86400 * 7)
                
            logger.info("campaigns_merged", target=target_campaign, source=source_campaign)
        except Exception as e:
            logger.error("campaign_merge_metadata_failed", target=target_campaign, source=source_campaign, error=str(e))
            
        return target_campaign

    async def _update_campaign_metadata(self, tenant_id: str, campaign_id: str, event: CanonicalEvent) -> None:
        """Phase 23A: Update campaign stage based on MITRE Kill Chain progression."""
        key = f"campaign_meta:{tenant_id}:{campaign_id}"
        meta_str = await self._redis.cache_get(key)
        
        if not meta_str:
            return
            
        try:
            # Handle both formats (ast string vs json) for safety, though we now use json
            if meta_str.startswith("{") and "'" in meta_str and '"' not in meta_str:
                import ast
                meta = ast.literal_eval(meta_str)
            else:
                meta = json.loads(meta_str)
                
            current_stage = meta.get("stage", "initial_access")
            new_tactic = self._extract_highest_confidence_tactic(event)
            
            stage_updated = False
            if new_tactic:
                current_idx = KILL_CHAIN_ORDER.index(current_stage) if current_stage in KILL_CHAIN_ORDER else -1
                new_idx = KILL_CHAIN_ORDER.index(new_tactic) if new_tactic in KILL_CHAIN_ORDER else -1
                
                if new_idx > current_idx:
                    meta["stage"] = new_tactic
                    stage_updated = True
            
            score_updated = False
            if event.ml_scores.meta_score > meta.get("meta_score", 0):
                meta["meta_score"] = event.ml_scores.meta_score
                score_updated = True
                
            # Escalate severity if score crosses threshold
            if meta["meta_score"] >= 0.9 and meta.get("severity") != "critical":
                meta["severity"] = "critical"
                score_updated = True
            elif meta["meta_score"] >= 0.75 and meta.get("severity") not in ["high", "critical"]:
                meta["severity"] = "high"
                score_updated = True
                
            if stage_updated or score_updated:
                await self._redis.cache_set(key, json.dumps(meta), ttl=86400 * 7)
                if stage_updated:
                    logger.info("campaign_stage_progressed", campaign_id=campaign_id, new_stage=meta["stage"], old_stage=current_stage)
                    
        except Exception as e:
            logger.warning("failed_to_update_campaign_meta", campaign_id=campaign_id, error=str(e))

    def _extract_highest_confidence_tactic(self, event: CanonicalEvent) -> Optional[str]:
        """Extract the MITRE tactic with the highest confidence from ML predictions."""
        if not event.ml_scores.mitre_predictions:
            return None
            
        best_pred = max(event.ml_scores.mitre_predictions, key=lambda x: x.confidence)
        if best_pred.tactic:
            # Normalize tactic name to match KILL_CHAIN_ORDER format
            normalized_tactic = best_pred.tactic.lower().replace(" ", "_").replace("-", "_")
            if normalized_tactic in KILL_CHAIN_ORDER:
                return normalized_tactic
                
        return None

    async def _find_entity_campaign(self, tenant_id: str, entity_id: str) -> Optional[str]:
        """Check Redis for entity → campaign membership."""
        state = await self._redis.get_entity_state(tenant_id, entity_id)
        if state and state.get("campaign_id"):
            return state["campaign_id"]
        return None

    def _get_primary_entity(self, event: CanonicalEvent) -> Optional[str]:
        if event.source_entity:
            return event.source_entity.identifier
        return None

    def _get_dst_entity(self, event: CanonicalEvent) -> Optional[str]:
        if event.destination_entity:
            return event.destination_entity.identifier
        return None
