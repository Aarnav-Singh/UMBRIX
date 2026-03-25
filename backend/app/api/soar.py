from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List, Dict, Any
from app.middleware.auth import require_analyst, require_admin, AuditLogger
from app.services.soar.engine import ExecutionEngine, Playbook, Node
from app.services.soar.actions import ActionRegistry
from app.repositories.postgres import PostgresRepository
from app.dependencies import get_app_postgres, get_app_engine

router = APIRouter(prefix="/soar", tags=["SOAR"])


@router.get("/providers", response_model=Dict[str, Any])
async def list_providers(claims: dict = Depends(require_analyst)):
    """List available SOAR action providers. Requires analyst role."""
    providers = {}
    for name, provider in ActionRegistry.providers.items():
        providers[name] = {
            "name": provider.name,
            "description": f"Actions capabilities for {provider.name}"
        }
    return {"status": "success", "data": providers}

@router.get("/playbooks", response_model=Dict[str, Any])
async def list_playbooks(
    repo: PostgresRepository = Depends(get_app_postgres),
    claims: dict = Depends(require_analyst)
):
    """List available SOAR playbooks. Requires analyst role."""
    playbooks = await repo.list_playbooks()
    return {
        "status": "success", 
        "data": [{
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "status": p.status,
            "nodes": p.nodes
        } for p in playbooks]
    }

@router.post("/playbooks")
async def create_playbook(
    request: Request,
    playbook_data: dict,
    repo: PostgresRepository = Depends(get_app_postgres),
    claims: dict = Depends(require_admin),
):
    """Create a new playbook from the UI."""
    playbook = await repo.create_playbook(
        name=playbook_data.get("name", "Unnamed Playbook"),
        description=playbook_data.get("description", ""),
        nodes=playbook_data.get("nodes", [])
    )
    return {"status": "success", "data": {"id": playbook.id}}

@router.post("/resume/{approval_id}")
async def resume_playbook(
    approval_id: str,
    payload: dict,
    request: Request,
    repo: PostgresRepository = Depends(get_app_postgres),
    engine: ExecutionEngine = Depends(get_app_engine),
    claims: dict = Depends(require_analyst)
):
    """Resume a playbook that's waiting for manual approval."""
    # Load paused state from PostgreSQL
    paused = await repo.get_paused_state(approval_id)
    if not paused:
        raise HTTPException(status_code=404, detail=f"No paused playbook for approval_id={approval_id}")

    # Load the playbook
    playbook_model = await repo.get_playbook(paused.playbook_id)
    if not playbook_model:
        raise HTTPException(status_code=404, detail=f"Playbook {paused.playbook_id} not found")

    # Convert to domain model
    nodes = [
        Node(
            id=n.get("id", "unknown"),
            action_type=n.get("action_type", ""),
            provider=n.get("provider", "unknown"),
            params=n.get("params", {})
        )
        for n in playbook_model.nodes
    ]
    playbook = Playbook(id=playbook_model.id, name=playbook_model.name, nodes=nodes)

    decision = payload.get("action", "approve")

    AuditLogger.log(
        "soar_playbook_resumed",
        request=request,
        claims=claims,
        target=approval_id,
        detail=f"playbook={paused.playbook_id} decision={decision}",
    )

    # Execute resume
    result = await engine.resume_playbook(playbook, paused.paused_node_index, decision)

    # Clear paused state
    await repo.clear_paused_state(approval_id)

    return {"status": "success", "message": f"Playbook resumed with action: {decision}", "results": result}

@router.post("/execute")
async def execute_playbook(
    playbook_id: str,
    request: Request,
    repo: PostgresRepository = Depends(get_app_postgres),
    engine: ExecutionEngine = Depends(get_app_engine),
    claims: dict = Depends(require_admin),
):
    """Execute a predefined playbook. Admin only."""
    # Ensure playbooks exist
    await repo.seed_playbooks_if_empty()
    
    playbook_model = await repo.get_playbook(playbook_id)
    if not playbook_model:
        raise HTTPException(status_code=404, detail="Playbook not found")

    AuditLogger.log(
        "soar_playbook_executed",
        request=request,
        claims=claims,
        target=playbook_id,
        detail=f"name={playbook_model.name}",
    )

    # Convert PostgreSQL model to Pydantic domain model for execution
    nodes = []
    for node_data in playbook_model.nodes:
        nodes.append(Node(
            id=node_data.get("id", "unknown"),
            action_type=node_data.get("action_type", ""),
            provider=node_data.get("provider", "unknown"),
            params=node_data.get("params", {})
        ))

    playbook = Playbook(
        id=playbook_model.id,
        name=playbook_model.name,
        nodes=nodes
    )
    
    # Execute the playbook
    result = await engine.execute_playbook(playbook)
    
    has_failures = any(node_res.get("status") in ("failed", "error_provider_missing", "error_exception") for node_res in result)
    is_paused = any(node_res.get("status") == "pending_approval" for node_res in result)

    if is_paused:
        return {"status": "paused", "message": "Playbook paused for manual approval", "results": result}
    
    if has_failures:
        AuditLogger.log(
            "soar_playbook_failed",
            request=request,
            claims=claims,
            target=playbook_id,
            detail=f"Partial failure detected during execution",
        )
        return {"status": "partial_success", "message": "Playbook executed with some failures", "results": result}
        
    return {"status": "success", "message": "Playbook executed successfully", "results": result}
