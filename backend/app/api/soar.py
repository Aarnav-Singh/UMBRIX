from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any
from app.middleware.auth import require_analyst, require_admin, AuditLogger
from app.services.soar.engine import ExecutionEngine, Playbook, Node
from app.services.soar.actions import ActionRegistry
from app.services.soar.action_manifest import ManifestRegistry
from app.repositories.postgres import PostgresRepository
from app.dependencies import get_app_postgres, get_app_engine

router = APIRouter(prefix="/soar", tags=["SOAR"])


@router.get("/manifests", response_model=Dict[str, Any])
async def list_container_manifests(claims: dict = Depends(require_analyst)):
    """List all registered containerised action manifests."""
    manifests = [
        {
            "name": m.name,
            "image": m.image,
            "capabilities": m.capabilities,
            "tags": m.tags,
            "description": m.description,
            "timeout_seconds": m.timeout_seconds,
            "memory_mb": m.memory_mb,
            "network_mode": m.network_mode,
        }
        for m in ManifestRegistry.all()
    ]
    return {"status": "success", "data": manifests}


@router.post("/execute-container")
async def execute_container_action(
    payload: dict,
    request: Request,
    engine: ExecutionEngine = Depends(get_app_engine),
    claims: dict = Depends(require_analyst),
):
    """
    Execute a single containerised SOAR action on-demand.

    Body:
      capability: str   — e.g. "isolate_host"
      context: dict     — action parameters (rendered by caller)
      manifest_name: str | null  — optional, pin to a specific manifest
    """
    capability = payload.get("capability")
    if not capability:
        raise HTTPException(status_code=422, detail="'capability' is required")

    context = payload.get("context", {})
    manifest_name = payload.get("manifest_name")

    if manifest_name:
        context["manifest_name"] = manifest_name

    AuditLogger.log(
        "soar_container_action_triggered",
        request=request,
        claims=claims,
        target=capability,
        detail=f"manifest={manifest_name or 'auto'}",
    )

    # Build a single-node playbook and run it for consistent audit trail
    node = Node(
        id=f"on-demand-{capability}",
        action_type=capability,
        provider="container",
        params=context,
    )
    pb = Playbook(id="on-demand", name=f"on-demand-{capability}", nodes=[node])
    result = await engine.execute_playbook(pb, tenant_id=claims.get("tenant_id", "default"))

    status = result[0].get("status", "error") if result else "error"
    return {"status": status, "results": result}


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
    result = await engine.resume_playbook(playbook, paused.paused_node_index, decision, tenant_id=claims.get("tenant_id", "default"))

    # Clear paused state
    await repo.clear_paused_state(approval_id)

    return {"status": "success", "message": f"Playbook resumed with action: {decision}", "results": result}

@router.post("/execute")
async def execute_playbook(
    playbook_id: str,
    request: Request,
    event_context: dict = None,
    repo: PostgresRepository = Depends(get_app_postgres),
    engine: ExecutionEngine = Depends(get_app_engine),
    claims: dict = Depends(require_admin),
):
    """Execute a predefined playbook with optional event context.
    
    The event_context dict is injected into Jinja2 templates within
    playbook node params, allowing alert-driven responses like:
      {{ src_ip }}, {{ hostname }}, {{ severity }}
    """
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
        detail=f"name={playbook_model.name} context_keys={list((event_context or {}).keys())}",
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
    
    # Execute the playbook with event context for Jinja2 template rendering
    result = await engine.execute_playbook(playbook, event_context=event_context, tenant_id=claims.get("tenant_id", "default"))
    
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
            detail="Partial failure detected during execution",
        )
        return {"status": "partial_success", "message": "Playbook executed with some failures", "results": result}
        
    return {"status": "success", "message": "Playbook executed successfully", "results": result}
