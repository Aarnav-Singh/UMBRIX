"""SOAR Execution Engine Core.

This module is responsible for orchestrating response actions
across various providers (Palo Alto, CrowdStrike, etc.) based
on high-level directives.
"""
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
    def __init__(self):
        # providers are now managed via ActionRegistry
        logger.info("Execution Engine initialized.")

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
        for node in playbook.nodes:
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
                logger.info(f"[SOAR] Playbook {playbook.id} paused at node {node.id} for approval.")
                break
                
            if status.startswith("error") or status == "failed":
                logger.warning(f"[SOAR] Playbook {playbook.id} stopped due to failure at node {node.id}.")
                break
                
        return results

execution_engine = ExecutionEngine()
