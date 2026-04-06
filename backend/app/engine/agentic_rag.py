"""Agentic RAG orchestrator using LangGraph.

LangGraph is an optional dependency. If it is not installed the orchestrator
degrades gracefully to a no-op stub that returns empty context dicts,
allowing the pipeline worker to start without the heavy graph runtime.
"""
from typing import TypedDict
import structlog

try:
    from langgraph.graph import StateGraph, START, END
    _LANGGRAPH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _LANGGRAPH_AVAILABLE = False
    StateGraph = START = END = None  # type: ignore[assignment]

from app.engine.rag_retriever import RagRetriever
from app.schemas.canonical_event import CanonicalEvent

logger = structlog.get_logger(__name__)

class AgenticRagState(TypedDict):
    tenant_id: str
    event: CanonicalEvent
    query: str
    
    # State accumulated
    historical_events: list[dict]
    graph_paths: list[dict]
    analyst_notes: list[dict]
    
    # Routing decision
    complexity_level: str  # 'low', 'high'

class AgenticRagOrchestrator:
    def __init__(self, retriever: RagRetriever):
        self.retriever = retriever
        if not _LANGGRAPH_AVAILABLE:
            logger.warning(
                "langgraph_not_installed",
                msg="AgenticRagOrchestrator running in no-op mode. "
                    "Install langgraph to enable graph-based RAG routing."
            )
            self.graph = None
            return
        self.graph = self._build_graph()

    def _build_graph(self):
        workflow = StateGraph(AgenticRagState)
        
        workflow.add_node("analyzer", self._node_analyzer)
        workflow.add_node("native_rag", self._node_native_rag)
        workflow.add_node("graph_rag", self._node_graph_rag)
        
        workflow.add_edge(START, "analyzer")
        
        # Conditional routing
        workflow.add_conditional_edges(
            "analyzer",
            self._route_complexity,
            {
                "low": "native_rag",
                "high": "graph_rag"
            }
        )
        
        workflow.add_edge("native_rag", END)
        workflow.add_edge("graph_rag", "native_rag") # High complexity gets BOTH graph and native RAG
        
        return workflow.compile()

    async def _node_analyzer(self, state: AgenticRagState) -> dict:
        """Determine if we need deep Graph RAG based on the event."""
        event = state["event"]
        score = event.ml_scores.meta_score
        
        complexity = "low"
        # High risk or specific lateral movement actions trigger Graph RAG
        action = event.action.value if hasattr(event.action, "value") else str(event.action)
        if score > 0.7 or action in ("lateral_movement", "c2", "exfil"):
            complexity = "high"
            
        logger.debug("agentic_rag_analyzer", event_id=event.event_id, complexity=complexity)
        
        event_type = event.event_type or ""
        msg = event.message or ""
        query = f"{action} {event_type} {msg}".strip()
        
        return {
            "complexity_level": complexity,
            "query": query,
            "historical_events": [],
            "graph_paths": [],
            "analyst_notes": []
        }

    def _route_complexity(self, state: AgenticRagState) -> str:
        return state["complexity_level"]

    async def _node_native_rag(self, state: AgenticRagState) -> dict:
        tenant_id = state["tenant_id"]
        query = state["query"]
        
        logger.debug("agentic_rag_native_search", tenant_id=tenant_id, query=query)
        events = await self.retriever.get_historical_context(tenant_id, query, limit=5)
        notes = await self.retriever.get_analyst_notes_context(tenant_id, query, limit=3)
        
        return {
            "historical_events": events,
            "analyst_notes": notes
        }

    async def _node_graph_rag(self, state: AgenticRagState) -> dict:
        tenant_id = state["tenant_id"]
        event = state["event"]
        
        # Extract source entity (e.g. src_ip or user)
        start_entity = ""
        if event.network and event.network.src_ip:
            start_entity = event.network.src_ip
        elif event.network and event.network.dst_ip:
            start_entity = event.network.dst_ip
            
        paths = []
        if start_entity:
            logger.debug("agentic_rag_graph_search", start_entity=start_entity)
            paths = await self.retriever.get_graph_context(tenant_id, start_entity, max_depth=3)
            
        return {
            "graph_paths": paths
        }

    async def retrieve_context(self, tenant_id: str, event: CanonicalEvent) -> dict:
        """Run the LangGraph workflow to gather RAG context for an event.

        Falls back to empty context if langgraph is not installed.
        """
        _empty = {"historical_events": [], "graph_paths": [], "analyst_notes": []}

        if self.graph is None:
            logger.debug("agentic_rag_noop", tenant_id=tenant_id)
            return _empty

        initial_state = {
            "tenant_id": tenant_id,
            "event": event,
            "query": "",
            "historical_events": [],
            "graph_paths": [],
            "analyst_notes": [],
            "complexity_level": "low"
        }
        
        final_state = await self.graph.ainvoke(initial_state)
        return {
            "historical_events": final_state.get("historical_events", []),
            "graph_paths": final_state.get("graph_paths", []),
            "analyst_notes": final_state.get("analyst_notes", [])
        }
