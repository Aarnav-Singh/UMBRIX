"""Real-time Collaboration API via WebSockets.

Enables 'Multiplayer Incident Analysis' where multiple analysts
can view the same incident and see presence indicators and live note updates.
"""
from __future__ import annotations

import json
from typing import Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import structlog
from app.dependencies import get_app_postgres

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/ws", tags=["collaboration"])

class ConnectionManager:
    def __init__(self):
        # Maps incident_id -> list of active WebSocket connections
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # Maps incident_id -> dict of user states
        self.presence_state: Dict[str, Dict[str, dict]] = {}

    async def connect(self, websocket: WebSocket, incident_id: str):
        await websocket.accept()
        if incident_id not in self.active_connections:
            self.active_connections[incident_id] = []
            self.presence_state[incident_id] = {}
        self.active_connections[incident_id].append(websocket)

    def disconnect(self, websocket: WebSocket, incident_id: str, user_id: str = None):
        if incident_id in self.active_connections:
            if websocket in self.active_connections[incident_id]:
                self.active_connections[incident_id].remove(websocket)
            
            if user_id and user_id in self.presence_state[incident_id]:
                del self.presence_state[incident_id][user_id]
                
            if not self.active_connections[incident_id]:
                del self.active_connections[incident_id]
                if incident_id in self.presence_state:
                    del self.presence_state[incident_id]

    async def broadcast_to_incident(self, incident_id: str, message: dict):
        if incident_id in self.active_connections:
            dead_sockets = []
            msg_str = json.dumps(message)
            for connection in self.active_connections[incident_id]:
                try:
                    await connection.send_text(msg_str)
                except Exception:
                    dead_sockets.append(connection)
            
            for dead in dead_sockets:
                self.disconnect(dead, incident_id)


manager = ConnectionManager()


@router.websocket("/collaborate/{incident_id}")
async def collaborate_ws(websocket: WebSocket, incident_id: str):
    """WebSocket endpoint for incident collaboration.
    
    Expected client messages:
    - {"type": "join", "user_id": "alice@org.com", "name": "Alice"}
    - {"type": "cursor", "user_id": "alice@org.com", "position": {"x": 100, "y": 200}}
    - {"type": "typing", "user_id": "alice@org.com", "field": "analyst_notes"}
    - {"type": "tag_added", "user_id": "alice@org.com", "tag": "False Positive"}
    """
    await manager.connect(websocket, incident_id)
    current_user_id = None
    
    try:
        while True:
            data = await websocket.receive_text()
            try:
                payload = json.loads(data)
                msg_type = payload.get("type", "unknown")
                user_id = payload.get("user_id", "anonymous")
                
                if msg_type == "join":
                    current_user_id = user_id
                    manager.presence_state[incident_id][user_id] = {
                        "name": payload.get("name", user_id),
                        "status": "active"
                    }
                    # Broadcast full presence state to everyone
                    await manager.broadcast_to_incident(incident_id, {
                        "type": "presence_update",
                        "users": manager.presence_state[incident_id]
                    })
                
                elif msg_type in ["cursor", "typing", "tag_added", "note_updated"]:
                    # Persist tags and notes to PostgreSQL before broadcasting
                    if msg_type in ("tag_added", "note_updated"):
                        try:
                            repo = get_app_postgres()
                            if msg_type == "tag_added":
                                await repo.save_incident_tag(
                                    incident_id=incident_id,
                                    user_id=user_id,
                                    tag=payload.get("tag", ""),
                                )
                            else:
                                await repo.save_incident_annotation(
                                    incident_id=incident_id,
                                    user_id=user_id,
                                    content=payload.get("content", ""),
                                )
                        except Exception:
                            logger.exception("ws_persist_failed", incident_id=incident_id)
                    # Re-broadcast to all other clients in this incident
                    await manager.broadcast_to_incident(incident_id, payload)
                    
            except json.JSONDecodeError:
                logger.warning("ws_invalid_json_received", incident_id=incident_id)

    except WebSocketDisconnect:
        manager.disconnect(websocket, incident_id, current_user_id)
        if current_user_id:
            await manager.broadcast_to_incident(incident_id, {
                "type": "presence_update",
                "users": manager.presence_state.get(incident_id, {})
            })
    except Exception as e:
        logger.error("ws_collaboration_error", error=str(e), incident_id=incident_id)
        manager.disconnect(websocket, incident_id, current_user_id)
