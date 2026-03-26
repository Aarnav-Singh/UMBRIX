"""SOAR Execution Engine Core.

This module is responsible for orchestrating response actions
across various providers (Palo Alto, CrowdStrike, etc.) based
on high-level directives.
"""
import uuid
import logging
import json
from typing import Dict, Any, List, Optional

from jinja2 import Template

from app.services.soar.actions import ActionProvider, PaloAltoProvider, CrowdStrikeProvider, ActionRegistry
from app.services.sse_broadcaster import broadcaster
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class Node(BaseModel):
    id: str
    action_type: str
    provider: str = "builtin"
    params: Dict[str, Any] = {}
    on_true: Optional[List["Node"]] = None
    on_false: Optional[List["Node"]] = None

Node.model_rebuild()

class Playbook(BaseModel):
    id: str
    name: str
    nodes: List[Node]

def _render_params(params: Any, context: dict) -> Any:
    """Recursively render Jinja2 templates in string values."""
    if isinstance(params, dict):
        return {k: _render_params(v, context) for k, v in params.items()}
    elif isinstance(params, list):
        return [_render_params(v, context) for v in params]
    elif isinstance(params, str) and "{{" in params:
        try:
            return Template(params).render(**context)
        except Exception as e:
            logger.error(f"Jinja render failed for '{params}': {e}")
            return params
    elif isinstance(params, str) and "{%" in params:
        try:
            return Template(params).render(**context)
        except Exception as e:
            logger.error(f"Jinja render failed for '{params}': {e}")
            return params
    return params

class ExecutionEngine:
    def __init__(self, postgres_repo=None):
        self._postgres = postgres_repo
        logger.info("Execution Engine initialized with Jinja2 templating and conditionals.")

    def set_postgres(self, repo) -> None:
        """Allow late-binding of the postgres repo (for DI after startup)."""
        self._postgres = repo

    async def execute_action(self, action_type: str, provider_name: str, context: Dict[str, Any]) -> str:
        """Executes an action via the specified provider."""
        if provider_name == "builtin" and action_type == "conditional":
            # the wrapper logic handles conditionals, so just return
            return "completed"

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

    async def execute_playbook(self, playbook: Playbook, event_context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Orchestrates the execution of multiple nodes with templating and branching."""
        ctx = event_context or {}
        results = []
        for idx, node in enumerate(playbook.nodes):
            await broadcaster.broadcast({
                "type": "soar_update",
                "playbook_id": playbook.id, 
                "node_id": node.id, 
                "status": "running"
            })
            
            # 1. Render dynamic parameters using Jinja2
            rendered_params = _render_params(node.params, ctx)
            
            # 2. Handle Builtin Conditional Node
            if node.action_type == "conditional":
                cond_val = str(rendered_params.get("condition", "")).strip().lower()
                is_true = cond_val in ("true", "1", "yes", "y")
                
                status = "completed"
                results.append({
                    "node_id": node.id,
                    "action_type": node.action_type,
                    "provider": "builtin",
                    "status": status,
                    "params": rendered_params,
                    "branch_taken": "on_true" if is_true else "on_false"
                })
                
                await broadcaster.broadcast({
                    "type": "soar_update",
                    "playbook_id": playbook.id, 
                    "node_id": node.id, 
                    "status": status
                })
                
                if self._postgres:
                    await self._postgres.save_soar_audit_log(
                        playbook_id=playbook.id,
                        node_id=node.id,
                        action_type=node.action_type,
                        provider="builtin",
                        status=status,
                        params={"branch_taken": "on_true" if is_true else "on_false", **rendered_params},
                    )
                
                branch = node.on_true if is_true else node.on_false
                if branch:
                    branch_pb = Playbook(id=playbook.id, name=f"{playbook.name}_branch", nodes=branch)
                    branch_results = await self.execute_playbook(branch_pb, ctx)
                    results.extend(branch_results)
                    
                continue
                
            # 3. Standard Action Provider Execution
            status = await self.execute_action(node.action_type, node.provider, rendered_params)
            
            await broadcaster.broadcast({
                "type": "soar_update",
                "playbook_id": playbook.id, 
                "node_id": node.id, 
                "status": status
            })
            
            if self._postgres:
                await self._postgres.save_soar_audit_log(
                    playbook_id=playbook.id,
                    node_id=node.id,
                    action_type=node.action_type,
                    provider=node.provider,
                    status=status,
                    params=rendered_params,
                )
            
            results.append({
                "node_id": node.id,
                "action_type": node.action_type,
                "provider": node.provider,
                "status": status,
                "params": rendered_params
            })
            
            if status == "pending_approval":
                # Persist pause state to PostgreSQL
                approval_id = str(uuid.uuid4())[:8]
                if self._postgres:
                    await self._postgres.save_paused_state(
                        playbook_id=playbook.id,
                        node_index=idx,
                        approval_id=approval_id,
                    )
                    logger.info(f"[SOAR] Playbook {playbook.id} paused at node {node.id}, approval_id={approval_id}")
                else:
                    logger.warning(f"[SOAR] Playbook paused but no postgres repo for state persistence")
                
                results[-1]["approval_id"] = approval_id
                break
                
            if status.startswith("error") or status == "failed":
                logger.warning(f"[SOAR] Playbook {playbook.id} stopped due to failure at node {node.id}")
                break
                
        return results

    async def resume_playbook(self, playbook: Playbook, from_node_index: int, decision: str, event_context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Continue execution from the paused node after approval."""
        if decision != "approve":
            logger.info(f"[SOAR] Playbook {playbook.id} rejected at node index {from_node_index}")
            return [{"status": "rejected", "message": "Playbook execution rejected by analyst"}]

        remaining_nodes = playbook.nodes[from_node_index + 1:]
        if not remaining_nodes:
            return [{"status": "completed", "message": "No remaining nodes after approval"}]

        # Resume logic uses standard execution on subset
        subset_pb = Playbook(id=playbook.id, name=f"{playbook.name}_resumed", nodes=remaining_nodes)
        return await self.execute_playbook(subset_pb, event_context)
