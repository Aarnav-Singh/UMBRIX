"""Narrative generation API — AI-powered event summarization."""
from __future__ import annotations
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.dependencies import get_app_clickhouse
from app.engine.narrative import NarrativeEngine
from app.middleware.auth import require_analyst

router = APIRouter(prefix="/narrative", tags=["intelligence"])
_engine = NarrativeEngine()

class NarrativeRequest(BaseModel):
    event_ids: list[str]
    context: str = ""

@router.post("/generate")
async def generate_narrative(
    body: NarrativeRequest,
    claims: dict = Depends(require_analyst),
    ch=Depends(get_app_clickhouse),
):
    if not body.event_ids:
        raise HTTPException(status_code=400, detail="event_ids must not be empty")
    tenant_id = claims.get("tenant_id", "default")
    # Limit to 20 event IDs max
    ids = body.event_ids[:20]
    # Query ClickHouse for the events
    from app.config import settings
    result = await asyncio.to_thread(
        ch.client.query,
        f"SELECT * FROM {settings.clickhouse_database}.events "
        "WHERE event_id IN {ids:Array(String)} AND tenant_id = {tenant_id:String} LIMIT 20",
        parameters={
            "ids": ids,
            "tenant_id": tenant_id,
        }
    )
    rows = [dict(zip(result.column_names, row)) for row in result.result_rows]
    
    if not rows:
        return {"narrative": "No matching events found.", "event_count": 0}
        
    narratives = []
    from app.schemas.canonical_event import CanonicalEvent
    from pydantic import TypeAdapter
    
    adapter = TypeAdapter(CanonicalEvent)
    
    for row in rows:
        # Convert ClickHouse row to dict
        event_dict = dict(row)
        # Parse into CanonicalEvent for the engine
        try:
            event_obj = adapter.validate_python(event_dict)
            narratives.append(_engine.generate(event_obj))
        except Exception as e:
            narratives.append(f"Error parsing event {event_dict.get('id')}: {str(e)}")
            
    return {"narrative": "\n\n".join(narratives), "event_count": len(rows)}
