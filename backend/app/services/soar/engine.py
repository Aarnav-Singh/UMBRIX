"""SOAR Execution Engine Core.

This module is responsible for orchestrating response actions
across various providers (Palo Alto, CrowdStrike, etc.) based
on high-level directives.
"""
import uuid
import logging
from typing import Dict, Any, List, Optional

from app.services.soar.actions import ActionProvider, PaloAltoProvider, CrowdStrikeProvider

logger = logging.getLogger(__name__)

from pydantic import BaseModel
from app.services.soar.actions import ActionRegistry
from app.services.sse_broadcaster import broadcaster


class Node(BaseModel):
    id: str
    action_type: str
    provider: str
    params: Dict[str, Any] = {}

class Playbook(BaseModel):
    id: str
    name: str
    nodes: List[Node]


class ExecutionEngine:
    def __init__(self, postgres_repo=None):
        self._postgres = postgres_repo
        logger.info("Execution Engine initialized.")

    def set_postgres(self, repo) -> None:
        """Allow late-binding of the postgres repo (for DI after startup)."""
        self._postgres = repo

    async def execute_action(self, action_type: str, provider_name: str, context: Dict[str, Any]) -> str:
        """Executes an action via the specified provider."""
        provider = ActionRegistry.get_provider(provider_name)
        if not provider:
            logger.error(f"[SOAR] Provider {provider_name} not found in registry")
            return "error_provider_missing"

        logger.info(f"[SOAR] Invoking {provider_name} for {action_type}")
        try:
            status = await provider.execute(action_type, context)
            if status == "failed":
                logger.error(f"[SOAR] Provider {provider_name} failed to execute {action_type}")
            return status
        except Exception as e:
            logger.exception(f"[SOAR] Exception in {provider_name} executing {action_type}: {e}")
            return f"error_exception"

    async def execute_playbook(self, playbook: Playbook) -> List[Dict[str, Any]]:
        """Orchestrates the execution of multiple nodes in a playbook."""
        results = []
        for idx, node in enumerate(playbook.nodes):
            await broadcaster.broadcast({
                "type": "soar_update",
                "playbook_id": playbook.id, 
                "node_id": node.id, 
                "status": "running"
            })
            
            status = await self.execute_action(node.action_type, node.provider, node.params)
            
            await broadcaster.broadcast({
                "type": "soar_update",
                "playbook_id": playbook.id, 
                "node_id": node.id, 
                "status": status
            })
            
            results.append({
                "node_id": node.id,
                "action_type": node.action_type,
                "provider": node.provider,
                "status": status,
                "params": node.params
            })
            
            if status == "pending_approval":
                # Persist pause state to PostgreSQL so resume is possible
                approval_id = str(uuid.uuid4())[:8]
                if self._postgres:
                    await self._postgres.save_paused_state(
                        playbook_id=playbook.id,
                        node_index=idx,
                        approval_id=approval_id,
                    )
                    logger.info(f"[SOAR] Playbook {playbook.id} paused at node {node.id}, approval_id={approval_id}")
                else:
                    logger.warning(f"[SOAR] Playbook {playbook.id} paused but no postgres repo for state persistence")
                
                results[-1]["approval_id"] = approval_id
                break
                
            if status.startswith("error") or status == "failed":
                logger.warning(f"[SOAR] Playbook {playbook.id} stopped due to failure at node {node.id}.")
                break
                
        return results

    async def resume_playbook(self, playbook: Playbook, from_node_index: int, decision: str) -> List[Dict[str, Any]]:
        """Continue execution from the paused node after approval.
        
        Args:
            playbook: The full playbook definition
            from_node_index: Index of the node that was paused (execution resumes from next)
            decision: 'approve' or 'reject'
        """
        if decision != "approve":
            logger.info(f"[SOAR] Playbook {playbook.id} rejected at node index {from_node_index}")
            return [{"status": "rejected", "message": f"Playbook execution rejected by analyst"}]

        # Resume from the node after the paused one
        remaining_nodes = playbook.nodes[from_node_index + 1:]
        if not remaining_nodes:
            return [{"status": "completed", "message": "No remaining nodes after approval"}]

        results = []
        for node in remaining_nodes:
            await broadcaster.broadcast({
                "type": "soar_update",
                "playbook_id": playbook.id,
                "node_id": node.id,
                "status": "running"
            })

            status = await self.execute_action(node.action_type, node.provider, node.params)

            await broadcaster.broadcast({
                "type": "soar_update",
                "playbook_id": playbook.id,
                "node_id": node.id,
                "status": status
            })

            results.append({
                "node_id": node.id,
                "action_type": node.action_type,
                "provider": node.provider,
                "status": status,
                "params": node.params
            })

            if status == "pending_approval" or status.startswith("error") or status == "failed":
                break

        return results
